# Lifecycle, tiering and batch jobs (Phase 12)

Packages: `internal/lifecycle` (rules, evaluator, scanner), `internal/tier`
(tier registry, S3/Azure/GCS backends, janitor, read-through cache),
`internal/batch` (job framework), `internal/storage/{meta,xl}` (transitioned
stubs), `internal/api/{lifecycle,tiering,batch}.go` (S3 and admin surface).

## 12a Lifecycle

`PUT/GET/DELETE /<bucket>?lifecycle` (actions `s3:PutLifecycleConfiguration`,
`s3:GetLifecycleConfiguration`; DELETE uses the Put action as S3 does). The
document is validated and stored canonically as a bucket config document.

* Rules: `ID` (unique, generated if absent), `Status`, `Filter` (`Prefix`,
  single `Tag`, `And` of prefix + tags + `ObjectSizeGreaterThan/LessThan`) or
  the legacy top-level `<Prefix>`; actions `Expiration` (`Days`, `Date`,
  `ExpiredObjectDeleteMarker`), `NoncurrentVersionExpiration`
  (`NoncurrentDays`, `NewerNoncurrentVersions`), `AbortIncompleteMultipartUpload`
  (`DaysAfterInitiation`), `Transition`, `NoncurrentVersionTransition`.
* "N days" is S3's: object time + N days **rounded up to the next midnight
  UTC**, so everything written on one UTC day expires together.
* **Overlapping rules.** All enabled matching rules contribute; the
  strongest action wins: permanent deletion of the version > transition >
  creation of a delete marker. Among several due transitions the coldest
  (largest `Days`) wins. A noncurrent version is judged only by the
  noncurrent actions; a delete marker only by `ExpiredObjectDeleteMarker`
  (when it is the only version left).
* Expiring a current version adds a delete marker in a versioned
  (Enabled/Suspended) bucket and removes the object in an unversioned one.
  Object lock outranks lifecycle: a protected version is skipped (counted).
* **Scanner.** Every node runs a scanner loop. For each bucket with a
  configuration it takes the cluster lock `_lifecycle/<bucket>` (waiting
  200 ms), so one node scans a bucket at a time; the leader skips the bucket
  if any node finished it less than `lifecycle.interval` ago (state in the
  system bucket). Walks `ListObjectVersions` in pages of 1000, grouping each
  key's versions, evaluating each; a token-bucket limiter
  (`lifecycle.opsPerSecond`, default 500/node) spaces listing entries and
  actions so a scan trickles beside foreground traffic.
* **Audit.** Every action is logged and published as a Phase 11 event
  (`s3:LifecycleExpiration:Delete`, `...:DeleteMarkerCreated`, new
  `s3:LifecycleTransition`) with principal `nanoio:lifecycle` and the rule ID
  in the request ID. Aborted uploads are logged only (S3 has no event).
* **Testing time.** `lifecycle.Clock` is injected (`api.LifecycleOptions.Clock`);
  tests move a fake clock 31 days instead of waiting.

## 12b Tiering

Admin (root by default; actions `nanoio:ManageTiers`, `nanoio:ListTiers`):

* `PUT /_nanoio/admin/tier` (JSON `tier.Config`; `?check=false` skips the
  write/read/delete probe; `?update=true` replaces credentials only),
  `GET /_nanoio/admin/tier` (secrets masked), `GET .../tier/check?name=`,
  `DELETE .../tier?name=` (refused while a lifecycle rule transitions to it,
  unless `force=true`). CLI: `nanoio admin tier-add|tier-ls|tier-check|tier-rm`.
* Tier names are upper case and may not shadow built-in S3 classes
  (`GLACIER`, ...). Backends: **s3** (any S3 endpoint, in-tree SigV4,
  multipart above `partSize`), **azure** (azblob SDK), **gcs**
  (cloud.google.com/go/storage). Tier configuration, including secrets, is
  stored **unencrypted** in the system bucket (root-only); encrypting it
  with the KMS is not done.

Transition: the scanner calls `Transition`: upload the version's stored bytes
to `<prefix><bucket>/<uuid>`, then commit a **stub** with
`TransitionObject(ifETag)`. If the version was rewritten meanwhile the commit
is refused and the uploaded copy deleted. Only xl and cluster back stubs
(`storage.Transitioner`); fs refuses tier creation and transition rules.

Stub format: `meta.Version.Transition{Tier, Object, VersionID, Time}` in
xl.meta, file format 5 (`FormatTiered`; older builds refuse it). The version
keeps size, ETag, metadata and lock; it loses `DataDir`/`Erasure`, and the
data directory is removed on every drive at commit (disk op `OpTransition`).
Heal skips stubs' shards and republishes the stub's xl.meta like any other.

Reading: `GetObject` returns `*storage.TransitionedError`; the API streams
from the tier (`openObject`, used by GET, CopyObject, UploadPartCopy and
batch replicate). The reader is seekable (ranges and decrypter skips cost
one remote range request). Encrypted objects transition as stored
ciphertext and decrypt as before.

* Headers: GET/HEAD report `x-amz-storage-class: <TIER>`; listings and
  version listings show the tier as `StorageClass`. `x-amz-restore:
  ongoing-request="false", expiry-date="..."` appears after a restore (S3
  semantics: the header exists only once a restore was requested), not on a
  never-restored stub.
* Restore-on-read: a straight read of a whole object up to half the cache
  size is teed into a node-local cache (`tier.cacheDir`, `cacheBytes`,
  `cacheTTL`, LRU) and later reads come from it. `POST ?restore` with
  `<Days>` fetches the object into the cache for that long (202; 200 if
  already restored) and emits `s3:ObjectRestore:Post/Completed`. The cache
  is **per node**, not cluster-wide.
* Reclaiming remote data: when a stub is removed (delete, version delete,
  overwrite of the null version) xl calls `OnTransitionFreed`; the
  **janitor** writes a note file and deletes the remote object with retries.
  A crash between commit and note leaves an orphan in the tier.
* Limits: a pool drain refuses transitioned objects (their stubs cannot be
  recreated on another set); transitioned objects count against nothing in
  the local capacity numbers; one transition uploads through one node.

## 12c Batch jobs

Admin (`nanoio:ManageBatch`, `nanoio:ListBatch`): `POST
/_nanoio/admin/batch/start` (YAML or JSON body → 202 `{"id"}`), `GET
.../list`, `GET .../describe?id=`, `POST .../cancel?id=`, `GET
.../template`. CLI: `nanoio admin batch-start --file F`, `batch-ls`,
`batch-describe --id`, `batch-cancel --id`, `batch-template`.

Definition (`apiVersion: v1`, exactly one section):

```yaml
replicate: {source: {bucket, prefix}, target: {endpoint, region, bucket, prefix,
            credentials: {accessKey, secretKey}}, filter, retry, concurrency}
expire:    {bucket, prefix, versions: latest|noncurrent|all, filter, retry, concurrency}
keyrotate: {bucket, prefix, encryption: {type: sse-kms|sse-s3, key}, filter, retry, concurrency}
filter:    {olderThan: 30d, newerThan, createdBefore, createdAfter,
            tags: [{key, value}], minSize, maxSize}
```

Execution:

* State is in the system bucket under `_batch/<id>/`: `job.json`,
  `enum.json` (cursor), `tasks/NNNNNNNN.json` (up to `taskItems` object
  versions), `done/NNNNNNNN.json` (counts, failure samples), `cancel`.
* Every node runs the same loops. A node that wins the lock `coord` becomes
  the job's **coordinator**: it enumerates the key space page by page into
  tasks (staying a bounded window ahead of the workers) and closes the job
  when all tasks are done. If it dies, another node takes over from the
  stored cursor.
* **Workers** on every node (`batch.workers`, default 2) claim a task with
  the lock `task/<n>` after taking one of the job's `concurrency` **slot**
  locks — so `concurrency` bounds tasks in flight *cluster-wide*. Each
  object is retried `retry.attempts` times with doubling delay; failures are
  reported per object (50 samples kept). Tasks are at-least-once; every
  operation is idempotent.
* Types: **expire** deletes (honouring object lock, emitting events);
  **keyrotate** re-wraps data keys (metadata only, `IfETag`) for
  SSE-KMS objects to `key`, or SSE-S3 objects to the latest version of the
  server key — an object of the other mode is skipped; **replicate** copies
  the latest version of matching objects, decrypting SSE-S3/KMS and reading
  through tiers, with content type, user metadata, cache headers and tags,
  and skips objects whose target already carries the same
  `x-amz-meta-nanoio-source-etag`. SSE-C objects fail (their key is not the
  server's). Replicate copies the latest version only, not history.
* A job is checked at start: the caller must be allowed the S3 actions it
  will perform on the bucket. The job itself then runs as the server.

## Not done

* A transitioned version moves only forward along the rule chain (WARM at
  30 days, then COLD at 90): the data is re-uploaded from the old tier to
  the new one and the old remote copy is freed. It never moves back to a
  warmer tier, and a version in a tier no rule mentions is left alone.
* No `ListObjectVersions` fields for restore state; no `x-amz-restore` for
  implicit read-through.
* Tier configuration secrets and batch job definitions (which carry a
  replicate target's credentials) are not encrypted at rest; they sit in the
  system bucket, readable by the root credential only, and secrets are
  masked in every listing.
* Batch replicate does not carry versions, ACLs or object lock settings.
* Per-node tier cache; no cluster-wide restore.
