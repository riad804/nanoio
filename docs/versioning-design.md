# Phase 7 design: object versioning

Status: **implemented** (all seven increments); see "Implementation notes and
deviations" at the end for where the code differs from this proposal.

Decisions taken:

1. *Who decides "versioned?"* — the backend, under the bucket shared lock;
   the `Versioned` flags are removed from `PutOptions` and `DeleteOptions`.
2. *Ordering key* — per-key sequence (`Seq = File.Gen + 1` at commit), not
   `ModTime`.
3. *Delete-marker reads* — AWS behaviour: latest is a marker and no
   `versionId` → 404 `NoSuchKey` + `x-amz-delete-marker: true`; explicit
   `versionId` of a marker → 405 `MethodNotAllowed` + `x-amz-delete-marker:
   true`.
4. *Interface* — keep the option structs (`GetOptions`, `DeleteOptions`,
   `ObjectRef` already carry `VersionID`); add `GetBucketVersioning` /
   `SetBucketVersioning`.

## 0. What exists today

* `internal/meta` already models what versioning needs: one `xl.meta` per key
  holding `File{Format, Versions[]}`, `Version.Type` is `object` or
  `deleteMarker`, `VersionID == ""` is the null version, `File.Add/Remove/Find`
  exist, and `Encode` sorts newest first. fs and xl write this format but only
  ever store one version (`file.Find("")`, `Latest()`).
* `StorageAPI` already carries version information in its option structs:
  `GetOptions.VersionID`, `DeleteOptions{VersionID, Versioned}`,
  `PutOptions.Versioned`, `ObjectInfo{VersionID, IsLatest, DeleteMarker}`,
  `ListObjectVersions`, `ObjectRef.VersionID`. fs and xl return
  `ErrNotImplemented` for the versioned paths.
* What does **not** exist: persisted bucket versioning state, the
  `?versioning` / `?versions` / `versionId` API surface, multi-version
  commit/heal/delete in xl, and a version ordering that is safe across nodes
  (today `newer()` orders by `ModTime`, which is wall-clock time).

## 1. Bucket versioning state machine

```
Unversioned --Enabled--> Enabled <--Suspended/Enabled--> Suspended
     (never reachable again from Enabled or Suspended)
```

| From \ To | Unversioned | Enabled | Suspended |
|-----------|-------------|---------|-----------|
| Unversioned | no-op | ok | ok (S3 accepts; behaves as unversioned, state recorded) |
| Enabled | **refused** (`IllegalVersioningConfigurationException`) | no-op | ok |
| Suspended | **refused** | ok | no-op |

* The state lives in the bucket's existing creation marker document
  (`.nanoio-bucket`, per drive in xl) as `{"created":…, "versioning":"",
  "versioningSeq":N}`. Absent field = Unversioned, so existing buckets need no
  migration.
* **Writes** go through `SetBucketVersioning`, which takes the bucket
  **exclusive** lock, validates the transition, bumps `versioningSeq` and
  replaces the marker on every drive atomically (temp → fsync → rename), with
  write quorum.
* **Reads** (`GetBucketVersioning`, and every object write) take the state
  from a read quorum of drives, the highest `versioningSeq` winning.
* Object writes hold the bucket **shared** lock for their duration (as they do
  today), so the state they read cannot change under them: an object write is
  entirely "before" or entirely "after" a state change.
* In a cluster the state must be uniform across sets. `SetBucketVersioning`
  fans out to every set and fails unless all succeed; `EnsureBuckets`
  (already run at start and periodically) additionally copies the state with
  the highest `versioningSeq` to sets that lag, so a partial failure
  converges.

**DECISION 1 — who decides "versioned?"** Today `PutOptions.Versioned` is set
by the API layer from bucket config, which is a check-then-act race with
`PutBucketVersioning`. *Recommended:* the backend decides, under the bucket
shared lock, and the `Versioned` booleans are removed from `PutOptions` and
`DeleteOptions`.

## 2. Version identity and ordering

* **VersionID**: UUIDv4 (`meta.NewVersionID`) for versions created while the
  bucket is Enabled. The **null version** is stored with `VersionID == ""` and
  shown to clients as `"null"` (request `versionId=null` ⇄ `""`). Writes while
  Unversioned or Suspended create/replace the null version.
* **Ordering** inside a key and in `ListObjectVersions` is *newest first*.
  Ordering by `ModTime` is not safe in a cluster: two nodes with skewed clocks
  can write versions of the same key in an order the clocks invert, and equal
  timestamps need a tiebreak. Every mutation of a key's version list is
  serialized (§4), so each new version is assigned a **per-key sequence
  number** `Seq = File.Gen + 1` at commit; order is `Seq` descending, which is
  total, clock-free and stable. `ModTime` stays as the user-visible
  Last-Modified.

**DECISION 2 — ordering key.** *Recommended:* `Seq` as above (files written
before this change have no `Seq`; they sort by `ModTime` below any versioned
entries, which is what they are). Alternative: keep `ModTime` order (simpler,
but listing order can disagree with causal order under clock skew).

## 3. `xl.meta` layout for versions

One file per key, as now; the payload grows.

```jsonc
{
  "format": 2,
  "gen": 7,                      // File.Gen: bumped on EVERY committed mutation
  "versions": [                  // newest first (by seq)
    { "type": "deleteMarker", "versionId": "c0a8…", "seq": 7, "modTime": "…" },
    { "type": "object", "versionId": "", "seq": 6, "modTime": "…",   // null version
      "size": 10, "etag": "…", "dataDir": ".nanoio-data-9f…",
      "parts": [...], "userMeta": {...}, "contentType": "…",
      "erasure": { "dataBlocks":4, "parityBlocks":2, "blockSize":1048576,
                   "index":3, "distribution":[...], "checksums":[...] } },
    { "type": "object", "versionId": "3b7e…", "seq": 4, ... }
  ]
}
```

* Each object version owns a **unique data directory**
  (`.nanoio-data-<token>/part.N`, as today), so versions never share files and
  deleting one version cannot touch another.
* `File.Gen` is the object-level compare-and-set counter. It replaces the
  per-version `Generation` field (kept readable for old files: `Gen` defaults
  to the newest version's `Generation`). **Every** mutation bumps it: add
  version, add marker, remove version. That is what makes version *deletion*
  as safe as version creation against two writers that both believe they hold
  the lock.
* **Format bump.** Files that use any versioning feature (more than one
  version, a delete marker, `gen`, `seq`) are written with `format: 2`. A build
  that only knows format 1 refuses to read them (`ErrUnsupported`, "never
  rewrite such a file"), which is safer than silently dropping versions.
  Every write by a versioning-aware build sets `gen` and `seq` (the
  compare-and-set counter needs them for unversioned buckets too), so in
  practice every key it touches becomes format 2; format-1 files remain
  readable and are rewritten as format 2 on their next mutation.
* Per-drive differences are unchanged: `Erasure.Index` and `Checksums` differ
  per drive; everything else in a version must be identical on every drive.

### Agreement across drives

Today drives agree on one version's fingerprint. With a list, drives agree on
the **whole file's identity**: a digest of the ordered tuple
`(versionId, seq, type, modTime, etag, size, dataDir)` per version, plus `gen`.
The latest-version fields are derived from the winning list. Read quorum is
still K agreeing drives. A drive that is behind (older `gen`) is a stale drive
exactly as a drive with an older single version is today.

## 4. Concurrency: how the namespace lock protects the version list

All mutations of one key's version list are a read-modify-write of one file.

1. **Lock order** is unchanged: bucket (shared) → key (exclusive) for PUT,
   DELETE (with or without version ID), CompleteMultipartUpload and heal's
   commit phase. The key lock is **per key, not per version**: a PUT and a
   DELETE of two different versions of the same key serialize. That is the
   price of keeping one file per key.
2. Under the key lock the writer reads the version list from a read quorum,
   computes the new list (§5), and commits with `CheckGen=true, PrevGen=gen`.
3. **Each drive** applies the mutation itself, under its per-key mutex: it
   re-reads its own `xl.meta`, rejects with `ErrConflict` if its `Gen` is
   greater than `PrevGen`, otherwise applies the *operation* (not the
   writer's list) to its own decoded file, writes the new file, and keeps the
   old bytes for rollback. Shipping the operation instead of a precomputed
   list means a drive that was one version behind can still accept the write
   and converge.
4. The lock is a fairness mechanism; `Gen` + CAS is the safety mechanism, as
   today: if a lease is lost mid-operation, at most one writer reaches a write
   quorum for generation `Gen+1`.
5. **Readers** take the key shared lock, read the list at quorum, and, for
   `GetObject`, pin the data directory of the version they resolved, so a
   concurrent DELETE of that version or an overwrite of the null version does
   not remove bytes under an open stream (the existing pin mechanism, now
   keyed by version data dir).
6. **Listing** does not lock keys: each key is confirmed by a quorum
   metadata read. A listing is not a snapshot across keys, but each key's
   version list is internally consistent (a single file).

New disk-level operation (the contract suite gains tests for each):

```
CommitObject(CommitRequest{Op: PutVersion|PutMarker|RemoveVersion, VersionID,
                           Version (for puts), CheckGen, PrevGen})
```

`PutVersion` with `VersionID == ""` replaces the null version and schedules
its data directory for removal at `Finish`. `RemoveVersion` removes the entry
and (at `Finish`) its data directory; removing the last version removes
`xl.meta` and prunes empty directories. `DeleteObject(bucket, object)` keeps
meaning "remove everything for this key" (used by heal for dangling objects
and by unversioned-bucket deletes).

## 5. Operation semantics

| Operation | Unversioned | Enabled | Suspended |
|-----------|-------------|---------|-----------|
| PUT | replace null | new version `UUID`, becomes latest; response `x-amz-version-id` | replace null (keeps other versions); response `x-amz-version-id: null` |
| DELETE, no versionId | remove null (key gone) | add delete marker `UUID` (latest); `x-amz-delete-marker: true`, `x-amz-version-id` = marker ID | add **null** delete marker, replacing and removing the null version's data |
| DELETE `versionId=V` | only `null` accepted | permanently remove V (object **or** marker); `x-amz-version-id: V`, `x-amz-delete-marker` true if it was a marker | same |
| GET/HEAD, no versionId | latest | latest | latest (the null version if it is latest) |
| GET/HEAD `versionId=V` | `null` only | version V | version V |
| ListObjects (not versions) | null objects | keys whose latest version is an object | same |

* Removing a delete marker "undeletes" the key: the next-newest version
  becomes latest.
* Removing the last remaining version removes the key entirely.
* `If-Match` / `If-None-Match` evaluate against the latest non-marker version
  as a plain PUT does against the current object (a latest delete marker
  counts as "does not exist").
* **CompleteMultipartUpload** creates a version exactly as PUT does.
  `UploadPartCopy` from `x-amz-copy-source-version-id` is accepted; plain
  `CopyObject` is still `ErrNotImplemented`.
* The ETag of a version never changes after it is written.

**DECISION 3 — delete-marker reads.** The request text says GET/HEAD on a
delete marker returns **405**. AWS S3 distinguishes two cases:

* `GET key` where the *latest* version is a delete marker → **404 NoSuchKey**
  with `x-amz-delete-marker: true` and `x-amz-version-id: <marker id>`.
* `GET key?versionId=<marker id>` → **405 MethodNotAllowed** with
  `x-amz-delete-marker: true`, `x-amz-version-id`, `Last-Modified`.

*Recommended:* the AWS behaviour above (clients such as `aws s3 cp`, SDK
`HeadObject` existence checks and `mc` depend on 404 for a deleted key).
Alternative: 405 in both cases, exactly as written.

## 6. `ListObjectVersions`

* Order: key ascending (UTF-8 bytes); within a key, newest first (`Seq`).
* Entries: `<Version>` (`Key, VersionId, IsLatest, LastModified, ETag, Size,
  StorageClass, Owner`) and `<DeleteMarker>` (`Key, VersionId, IsLatest,
  LastModified, Owner`); `CommonPrefixes` with `delimiter`; null version
  appears as `VersionId` `null`.
* Pagination: `key-marker` + `version-id-marker`; response
  `NextKeyMarker` / `NextVersionIdMarker`, `IsTruncated`. Semantics: resume
  strictly after `(key-marker, version-id-marker)` in the order above. If
  `version-id-marker` is empty, resume at the first entry of the next key.
  If the marker version no longer exists (deleted between pages) resume at
  the first version of that key *older* than the marker's `Seq`... which is
  unknowable once it is gone; the rule is therefore "skip to the next key",
  as S3 does. Documented in the API test.
* `max-keys` counts versions and markers and common prefixes together.
* In the cluster the sets' pages are merged by `(key, seq desc)`, with the
  same per-set deadline and strict/partial policy as `ListObjects`.

## 7. Storage layer changes

**Interface (DECISION 4).** The request says every `StorageAPI` method gains
a `versionID` parameter. Today the version already travels in option structs
(`GetOptions`, `DeleteOptions`, `ObjectRef`), and most methods (buckets,
multipart parts) have no version to address. *Recommended:* keep options
structs (no churn for the ~40 call sites and fakes), remove the two
`Versioned` flags (DECISION 1), and add:

```go
GetBucketVersioning(ctx, bucket) (VersioningConfig, error)   // state + seq
SetBucketVersioning(ctx, bucket, state VersioningState) error
```

plus `ListObjectVersions` options gaining `VersionIDMarker` (already present).
Alternative: add an explicit `versionID string` parameter to
`GetObject/StatObject/DeleteObject/CopyObject/UpdateObjectMetadata`
(signatures change, behavior identical).

**meta package.** Pure, table-tested functions shared by fs and xl so they
cannot drift: `ApplyPut(file, version, opts)`, `ApplyMarker`, `ApplyRemove`,
`Resolve(file, versionID)`, `Page(...)` for version listing; `File.Gen`,
`Version.Seq`; ordering by `Seq` then `ModTime` then `VersionID`.

**xl.** Commit (§4); `readMeta` keeps the list; `objState` agreement on
whole-file identity; reader resolves a version and pins its data dir;
**heal** repairs per version: for each version in the winning list, drives
missing that version's shards (or the version entry) are rebuilt, and the list
is committed with `gen` unchanged (unconditional commit, as today's repairs);
**scan/orphans**: `referenced()` already treats every version's data dir as
live; **delete of a version** removes only its data dir.

**fs.** Same `meta` functions; same per-key flock/lock discipline; data dirs
per version; GC treats all versions' data dirs as live (it already iterates
`file.Versions`).

**Cluster.** `ObjectRef`/options carry version IDs through routing; a
version lookup probes sets as an object lookup does; bucket versioning state
fan-out and reconciliation as in §1; multipart upload IDs unchanged.

## 8. API surface

* `PUT /bucket?versioning` body `<VersioningConfiguration><Status>Enabled|
  Suspended</Status></VersioningConfiguration>`; `MFADelete` present →
  `NotImplemented`; any other status → `MalformedXML`; Enabled→Unversioned is
  unrepresentable (there is no status for it) so the refusal is for an empty
  `<Status/>` on a bucket that was ever versioned.
* `GET /bucket?versioning`: `<VersioningConfiguration/>` for a never-enabled
  bucket, otherwise `<Status>`.
* `GET /bucket?versions` → ListVersionsResult.
* `versionId` query on GET/HEAD/DELETE object; `x-amz-version-id` and
  `x-amz-delete-marker` response headers on PUT, GET, HEAD, DELETE,
  CompleteMultipartUpload; DeleteObjects (multi-delete) accepts per-key
  `VersionId`.
* IAM: `s3:GetObjectVersion`, `s3:DeleteObjectVersion`, `s3:PutBucketVersioning`,
  `s3:GetBucketVersioning`, `s3:ListBucketVersions` are used when the request
  names a version (GET/DELETE) or the sub-resource; the policy engine already
  matches arbitrary action strings.

## 9. Test plan

1. `meta`: table tests for `ApplyPut/Marker/Remove/Resolve` across the three
   bucket states, ordering by `Seq`, format-1/2 round trips, a format-2 file
   refused by a format-1 decoder.
2. State machine: every cell of the transition table; refusal; persistence
   across restart; concurrent `Set` + PUT (writes see old or new state, never
   a mixture).
3. `storagetest` versioning suite run against fs, xl (4 layouts), the
   distributed xl set and the cluster store: PUT/GET/DELETE/list in all three
   states, null-version replacement, marker create/remove (undelete),
   removing the last version, suspended semantics, multipart creating
   versions, snapshot reads of a version surviving its deletion.
4. **Interleaving test (requested):** N goroutines PUT, DELETE (marker),
   DELETE-version and Suspend/Enable on a small key set while a checker
   asserts after every operation and at the end that `ListObjectVersions`
   returns (a) keys ascending, (b) within a key strictly descending `Seq`,
   (c) exactly the versions the operation history says exist, (d) identical
   order on repeated listings and from every node of a 3-node cluster.
5. Linearizability checker extended to a register-with-history model for
   multi-node histories (put/delete/delete-version/get-version).
6. Damage tests per version: kill shards of a non-latest version, heal,
   verify; delete-version while another version is being read.
7. API tests: XML shapes, headers, 404/405 cases (DECISION 3), pagination
   with `null`, `If-Match` against markers, IAM action mapping,
   `aws s3api` smoke script in the verification instructions.

## 10. Known limits (proposed to document, not solve)

* No lifecycle: noncurrent versions are kept forever; disk use grows.
* One lock per key (not per version), so version operations on one key
  serialize.
* An `xl.meta` with very many versions is rewritten whole on each mutation
  (O(versions) per write); a 10 000-version key costs ~MBs per PUT. A per-key
  version cap or a split layout is future work.
* MFA delete, replication and object lock are out of scope.
* `CopyObject` remains unimplemented.

## 11. Increments

1. `meta`: `Gen`, `Seq`, ordering, pure apply/resolve functions + tests
   (no behavior change).
2. Bucket versioning state: fs + xl + cluster storage, API
   `?versioning`, state-machine tests.
3. fs versioned PUT/GET/DELETE + conformance suite.
4. xl: `Disk` mutation ops, multi-version commit/CAS, resolve/pin, delete;
   contract suite; distributed.
5. xl heal/scan per version; damage tests.
6. `ListObjectVersions` (fs, xl, cluster) + API surface + headers + IAM.
7. Interleaving + linearizability tests; docs; TODO.

## 12. Implementation notes and deviations

What was built matches sections 1-9 with these differences and additions:

* **`xl.meta` is format 2 for every write** by this build, not only for files
  that use versioning features: the compare-and-set counter (`gen`, `seq`) is
  needed for unversioned buckets too. Format-1 files remain readable and are
  rewritten on their next mutation.
* **A drive numbers an un-numbered commit itself** (`CommitRequest.Seq == 0`
  means "next generation"), for single-drive callers and tests. xl always
  numbers its writes, once, before sending them to the drives.
* **Delete markers on reads are a typed error**, `*storage.DeleteMarkerError`,
  which matches `ErrObjectNotFound` when the latest version was asked for
  and `ErrIsDeleteMarker` when the marker's own ID was named, and carries the
  marker's ID and time for the response headers (Decision 3).
* **Version IDs at the API boundary:** `null` is the null version;
  `storage.ReportedVersionID` omits version IDs entirely for a bucket that
  never had versioning.
* **xl caches a bucket's versioning state for 2s for reporting only** (the
  `x-amz-version-id` header on reads). Writes read the state under the bucket
  lock, so a stale cache can only make a read omit or add a version header
  for up to 2s after a change made on another node.
* **Heal republishes whole version lists** with an unconditional
  `OpReplace`: each drive is made to list exactly the agreed versions, with
  its own erasure index and checksums, rebuilding any version whose shards
  are missing or damaged. A version held by a minority is dropped.
* **Unversioned `DeleteObject` (no version ID, bucket never versioned)**
  keeps waiting for every drive and removes the key from all of them, as
  before versioning: it carries no generation, so a late one could remove a
  newer write's copy. Every versioned change is generation-conditional and
  returns at write quorum.
* **Cluster:** `ListObjectVersions` is strict (a set that cannot answer
  fails the listing; there is no partial mode). `Drain` refuses a pool that
  holds a versioned bucket, because moving a key would copy only its latest
  version.
* **Per-version locks** were not added: one lock per key, as proposed.

### Tests that pin the behavior

| Test | What it pins |
|------|--------------|
| `meta/versions_test.go` | apply/resolve/ordering by `Seq` not clock, format selection, legacy decode |
| `disktest` `VersionOps`, `VersionReplace`, `ConditionalCommit` | per-drive operations, rollback, CAS, repair |
| `storagetest` `VersioningState` | the state machine on fs, xl (4 layouts), distributed xl, cluster |
| `storagetest` `RunVersioned` | enabled/suspended/unversioned semantics, markers, removal, multipart, snapshot reads, preconditions |
| `VersionedListing*`, `VersionedInterleavedModel` | listing order newest first, paging, markers, stable across repeats, equal to a reference model |
| `VersionedConcurrentListing` | listers never see disorder while writers and deleters run |
| `xl/versions_test.go` | heal of every version, stray minority versions, random damage of versioned keys |
| `TestVersionedAcrossNodes` | linearizability of the version-list model over three nodes |
| `TestVersionedSurvivesNodeLossAndLostReplies` | acknowledged versions survive crashes and lost replies |
| `api/versioning_test.go` | XML, headers, 404/405 distinction, pagination markers, IAM actions |
