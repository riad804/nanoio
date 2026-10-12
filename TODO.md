# TODO

Every unimplemented area is listed here. Code that is out of scope returns
`storage.ErrNotImplemented` explicitly; nothing is silently stubbed.

## Phase 0 - done
- [x] `go.mod`, repo skeleton
- [x] `internal/storage`: `StorageAPI`, `Locker`, option/result types, error sentinels, name validation
- [x] `internal/meta`: envelope + JSON codec, golden + fuzz tests
- [x] `internal/archtest`: import-rule test

## Phase 1 - single node, `fs` backend: done
- [x] `internal/storage/internal/fsutil`: `SafeJoin`, `WriteFileSync`, `SyncDir`, `MkdirAllSync`
- [x] `internal/bucket/nslock`: in-memory `storage.Locker`
- [x] `internal/storage/fs`: buckets (make, list, exists, info, delete) and objects (put, get, stat, delete, list)
- [x] `internal/storage/storagetest`: conformance suite
- [x] `internal/config`: NANOIO_* env + JSON file
- [x] `cmd/nanoio`: flags, wiring, graceful shutdown (no HTTP listener yet)
- [x] `Makefile`: `make test`, `make run`

## Phase 2 - S3 API: done
- [x] `internal/api`: path-style + virtual-host routing, XML types, handlers, error mapping with exhaustiveness test over `storage.AllErrors()`
- [x] ListObjectsV1 and V2 with continuation tokens, delimiter, `encoding-type=url`, `start-after`, `fetch-owner`
- [x] DeleteObjects (`aws s3 rm --recursive`), ranges, conditional GET/HEAD, Content-MD5 / x-amz-content-sha256 verification
- [x] aws-chunked decoding (SigV4 streaming and trailing-checksum uploads)
- [x] HTTP listener, graceful drain, `address` / `domains` / `region` config

## Phase 3 - authentication and authorisation: done
- [x] `internal/auth`: SigV4 header auth, presigned URLs, streaming chunk signing (incl. signed trailers); validated against the official AWS test suite (34 vectors, vendored under `internal/auth/testdata`) and the AWS-documented chunk chain
- [x] `internal/iam`: root credential, users from a JSON file, canned and custom policy documents (Allow/Deny, Action/NotAction, Resource/NotResource, conditions), `${aws:username}`
- [x] API: authenticate every request, authorise each action before touching storage, per-key authorisation in multi-delete, signed body hashes verified
- [x] Startup refuses to run without root credentials unless `--insecure-no-auth` is given

## Phase 4 - multipart upload and garbage collection: done
- [x] CreateMultipartUpload, UploadPart, UploadPartCopy (whole object or `x-amz-copy-source-range`, with copy-source conditions and source read authorisation), ListParts, ListMultipartUploads, CompleteMultipartUpload, AbortMultipartUpload
- [x] ETag = MD5 of the concatenated binary part MD5s + `-N`; part limits (1..10000, 5 MiB minimum for every part but the last, 5 GiB maximum); parts must be listed in ascending order with their ETags
- [x] Parts are re-uploadable atomically; parts of a finished object stay separate files and are read across with seek/range support
- [x] `fs.GC` and a background collector: expired uploads, staging debris, orphaned part files, orphaned object data dirs, empty key dirs (config `uploadExpiry`, `gcInterval`)
- [x] A bucket with incomplete uploads is not empty (BucketNotEmpty), as in S3; forced delete discards them

## Phase 5 - erasure-coded backend (`internal/storage/xl`): done
- [x] Reed-Solomon (`klauspost/reedsolomon`) K data + M parity shards over 2-32 drives, per-key rotation of the shard layout
- [x] Per-block SHA-256 stored inline with every shard; reads verify only the blocks they touch and reconstruct from parity on a mismatch
- [x] `xl.meta` is the same JSON-in-CRC-envelope as fs, replicated to every drive with per-drive `Erasure.Index` and checksum root
- [x] Quorum reads (K agreeing drives), quorum writes (K, or K+1 when K==M) with per-drive rollback
- [x] Heal: reconstruct missing/outdated/corrupt shards (shallow or deep), dangling-remnant removal, read-triggered repair queue, replacement-drive formatting, background scanner, upload expiry, orphan and staging collection
- [x] Passes the shared `storagetest` conformance suite unchanged in 4 layouts; randomised shard-killing tests
- [x] `fs` fixed alongside: multipart snapshot reads now pin their data directory (`internal/storage/internal/pins`)

## Phase 6 - distributed NanoIO: done (see docs/cluster-operations.md)
- [x] 1. `disk.Disk` interface under xl, `Local` implementation, shared `disktest` contract suite, `xl.NewWithDisks`
- [x] 2. Authenticated RPC (`internal/cluster/rpc`, `rpcauth`: HKDF per-node keys, HMAC over method/path/args/body/node/time/nonce, replay cache, signed responses, mutual TLS, fail-closed TLS requirement, rotation procedure), remote drives (`xl/disk/remote`, passes the same contract suite), fault-injecting network (`faultnet`) with partition/delay/crash/lost-reply tests
- [x] 3. dsync-style lock manager (`internal/cluster/dsync`): quorum leases, refresh, loss signalling, restart quarantine; mutual-exclusion checker under partition/crash/delay
- [x] 4. Per-object generation + conditional commit on every drive; linearizability checker over multi-node histories with crash/partition/lost replies; mutation-checked
- [x] 5. Consistent-hash ring over sets, pools, probe-on-miss after a pool add, cross-set LIST with per-set deadlines and strict-by-default partial-result policy, drain
- [x] 6. `/_nanoio/health/{live,ready,cluster}`, heartbeats (health only), `nanoio admin status|scan|decommission`, bucket-name validator and reserved-namespace tests

## Known limitations of distributed mode
- [ ] **Not a consensus system.** Membership is static configuration; there is no automatic rebalancing, no node join without a config change and rolling restart, and an even split (2+2) is unavailable on both sides.
- [x] **Slow and failing drives (done):** a write returns once its write quorum is durable plus `stragglerGrace` (default 500ms); lagging writers are evicted mid-stream and healed afterwards; commits and metadata reads return at quorum; remote drives sit behind a per-drive circuit breaker (fails fast, one half-open probe, exponential backoff to 30s).
- [ ] **Still unhedged:** a GET reads the K data shards and only reaches for parity on *error*, so a drive that is slow but not failing slows the read (no hedged/parallel parity read). Deletes, bucket create/delete, multipart bookkeeping and listing confirmations still wait for every drive; deletes deliberately, because a late delete would remove a later write's copy (a commit carries a generation, a delete does not). A drive that hangs costs one RPC timeout (30s metadata, 5min bulk) before the breaker opens.
- [ ] **No retries** in the RPC layer: a transient failure counts as a failed drive for that operation.
- [ ] **Locks have no queue**: contenders retry with jittered backoff, so a stream of readers can starve a writer. A lock server grants nothing for one TTL (30s) after a restart, so a whole-cluster cold start refuses lock-taking requests for that long.
- [ ] **Every node holds the cluster secret** (needed to derive peers' keys). Per-node keys limit replay and cross-node reuse; a compromised node is not contained. Rotation is a manual three-step rolling restart; nothing verifies that every node picked the new secret.
- [ ] **A pool add does not rebalance.** Once there is more than one pool, an object lookup that misses on the ring's set probes every other set (S-1 extra stats for a GET/PUT of a key that does not exist). Drain moves multipart objects part for part (the ETag is kept) and refuses while uploads are in progress; marking a pool draining needs a config change and restart on every node.
- [ ] **Generations restart at 1 after delete and re-create**, so a drive that missed the delete and later returns holds an older object under a higher generation until healed (it is outvoted by quorum, then overwritten by heal).
- [ ] **Cross-set LIST costs N pages per page** and inherits xl's O(objects x drives) listing. The strict policy fails a whole listing for one unavailable set; `allowPartialList` trades that for an incomplete, header-marked result.
- [ ] **IAM and bucket configuration are per-node files**, only eventually consistent across nodes by operator action; there is no replicated config store.
- [ ] **Admin API is minimal** (status, scan, decommission) and unauthenticated health reports expose counts only. No metrics endpoint.
- [ ] Tests run nodes in one process over an in-memory network (plus three loopback processes-in-one for TLS); no multi-host, multi-process soak or Jepsen-style run has been done.

## Phase 7 - object versioning: done (see docs/versioning-design.md)
- [x] State machine Unversioned -> Enabled <-> Suspended, `PUT/GET ?versioning`, persisted per bucket with a change sequence, reconciled across sets
- [x] Version IDs (UUID), null version, delete markers, `versionId` on GET/HEAD/DELETE, `x-amz-version-id` / `x-amz-delete-marker`, 404-vs-405 for markers, multi-delete with versions
- [x] `ListObjectVersions` with key/version-id markers; ordering by a per-key sequence, not clocks
- [x] fs, xl (multi-version commit, CAS on the whole version list, per-version heal) and cluster implementations behind one conformance suite

## Known limitations of versioning
- [ ] **No lifecycle**: noncurrent versions and delete markers are kept forever; disk use grows with every overwrite of a versioned key.
- [ ] **One lock and one `xl.meta` per key**: version operations on one key serialize, and the whole version list is rewritten on every mutation (O(versions) per write). A key with tens of thousands of versions will be slow; there is no cap.
- [ ] **Drain cannot move versioned buckets** (it would copy only the latest version); decommissioning a pool that holds one is refused.
- [x] `CopyObject` with `x-amz-copy-source` (and `?versionId=` in it) is implemented in the API layer (Phase 9); a self-copy in a versioned bucket updates the version in place instead of creating a new one (MinIO's behaviour, not AWS's).
- [ ] MFA delete, replication and S3 Inventory are not implemented. (Object lock: Phase 8, below.)
- [ ] `ListObjectVersions` has no partial-result mode in the cluster (unlike ListObjects).
- [ ] The versioning state read for reporting version IDs may be up to 2s stale on a node other than the one that changed it.
- [ ] Generations (and so version sequence numbers) restart at 1 when a key's last version is removed.

## Phase 8 - S3 Object Lock: done (see docs/object-lock-design.md)
- [x] `CreateBucket` with `x-amz-bucket-object-lock-enabled: true`: the bucket is born versioned and locked in one marker write; irreversible, versioning can never be suspended on it
- [x] `PutObjectLockConfiguration` / `GetObjectLockConfiguration` (default retention: mode + days or years; the lock itself cannot be turned off or enabled later)
- [x] Per-object `x-amz-object-lock-mode` / `-retain-until-date` / `-legal-hold` on PUT and multipart initiate; returned on GET/HEAD
- [x] `PutObjectRetention` / `GetObjectRetention` / `PutObjectLegalHold` / `GetObjectLegalHold`, per version
- [x] Enforcement in one rule (`meta.CheckRemove`, `meta.CheckLockChange`), applied by the coordinator under the key lock **and** again by every drive: COMPLIANCE can only be extended, by anyone, root included; GOVERNANCE needs `s3:BypassGovernanceRetention` *and* `x-amz-bypass-governance-retention: true`; a legal hold blocks deletion whatever else is true; a delete of a locked version is `403 AccessDenied`; a delete without a version ID adds a delete marker and succeeds
- [x] Table-driven matrices at three levels: `meta` (rules), `storagetest` (every backend), `api` (principals x header x state over HTTP)

### What COMPLIANCE does and does not promise
COMPLIANCE retention is enforced **by this server**. There is no "force unlock" path in the API, the admin CLI or the storage interface, and the only
ways a version leaves a key (version delete, null-version replace, whole-key delete, forced bucket delete) all go through the same rule on the
coordinator and on every drive. It is **not** a promise against someone who can touch the drives: an operator with disk access can edit or
delete `xl.meta` and the data directories, restore a drive from an older copy, or reformat it, and the retention is gone with them. MinIO has the
same caveat. If you need protection from the operator, the answer is a different trust boundary (offsite copy, hardware WORM, separate admin
domain), not this feature.

## Known limitations of object lock
- [ ] **Retention is judged against the clock of the node that coordinates the change** (sent to every drive, so the drives of one set agree). Two nodes whose clocks differ disagree by that much about "expired". Peers that are more than `rpcauth.Window` (30s) apart cannot exchange RPCs at all, so inside a cluster the disagreement is bounded by about a minute; nothing bounds it against real time. Run NTP. A node whose clock runs fast lets a version go early by that much; one that runs slow keeps it longer.
- [ ] **A past `retain-until-date` is refused for both modes** (S3 does the same), against the server's clock: a client whose clock is ahead of the server's by more than the margin it chose will see `InvalidArgument`. There is no tolerance window.
- [ ] **Expired retention protects nothing and can be replaced**, including COMPLIANCE; a legal hold still blocks.
- [ ] **Object lock can only be enabled when the bucket is created.** Enabling it on an existing versioned bucket (which S3 now allows) would have to account for null versions and is not implemented.
- [ ] **Dangling-object cleanup is not a lock bypass but is not lock-aware either**: heal removes a key that no read quorum can reconstruct. For a locked key that means data already lost; the drives still refuse (`Disk.DeleteObject` checks the file it can read), so debris may be left for an operator.
- [ ] **A drive restored from a backup older than a retention change** holds the old, weaker lock under an older generation; quorum outvotes it and heal overwrites it. If more than half of a set is restored from such backups, the weaker state wins; backups are outside the guarantee.
- [ ] **Rolling upgrade**: nodes must all run a build that knows `bucket.settings.get` / `bucket.lock.set` before a lock bucket is created. Version-list files containing a lock are `xl.meta` format 3, which older builds refuse to read (by design: they would drop the lock on rewrite).
- [x] `CopyObject` does not inherit retention or legal hold from its source; it applies the request's lock headers or the destination bucket's default. An in-place copy refuses lock headers.
- [ ] Object lock status is not in `ListObjectVersions` output, and there are no S3 event notifications for retention changes.
- [ ] `DeleteObjects` honours the bypass header per key (AccessDenied for a key the principal may not bypass); the `s3:BypassGovernanceRetention` check is made once per key, before any deletion.
- [ ] With `--insecure-no-auth` anyone may send the bypass header and it is honoured; COMPLIANCE is unaffected.

## Known limitations of the xl backend
- [ ] **One erasure set, one process.** No pools, no multiple sets, no expansion; the drive list and parity are fixed for the life of the deployment (reordering is detected and refused; changing parity requires a re-encode that is not implemented). Distributed (network) drives are the natural next phase.
- [ ] **Hash choice**: SHA-256 (stdlib, hardware accelerated) instead of HighwayHash/BLAKE2, to avoid another dependency. The algorithm is recorded per object (`checksums[].algorithm`), so another can be added without a format change.
- [ ] **No scheduled deep scrub.** The background scanner is shallow (presence and size); a bit flip in a shard that reads never touch is only found by `Scan(ctx, true)`, which has no admin command or API yet. Add a configurable deep-scrub cadence and an admin endpoint/CLI (`nanoio heal`).
- [ ] **No drive health tracking.** A slow or flapping drive is retried on every operation; a PUT waits for every shard writer, so one stalled drive stalls writes. Needs per-drive timeouts, a circuit breaker, and "return at write quorum, finish the rest in the background".
- [ ] **Unmounted-disk hazard is only partly guarded.** A vanished drive directory is never recreated, but an empty mount point left behind by an unmounted disk looks like a blank replacement and will be formatted and filled on the parent filesystem. Add an optional "must be a mount point" check.
- [ ] Listing reads `xl.meta` from every drive for every key it returns (quorum confirmation), and a scan walks every object: O(objects x drives). Needs a metadata cache or per-drive listing index.
- [ ] Healing re-reads and re-encodes a whole object, not just the damaged blocks.
- [ ] Per-object read repair is queued best-effort (a full queue drops requests; the periodic scan rediscovers them).
- [x] `UpdateObjectMetadata` is implemented in fs, xl and cluster (Phase 9). `StorageAPI.CopyObject` itself stays `ErrNotImplemented` in every backend: the API composes copies from Get/Put/UpdateObjectMetadata.

## Known limitations of multipart / GC
- [ ] **Part limits are checked at completion, as in S3**, so an undersized part is only reported by CompleteMultipartUpload.
- [x] `CopyObject` works (Phase 9), so `aws s3 cp s3://a s3://b` and `aws s3 mv` work.
- [ ] CompleteMultipartUpload holds the upload, bucket and key locks while linking parts and committing; completion of a 10,000-part upload blocks writers of that one key for that duration. S3's keep-alive whitespace on slow completions is not sent.
- [ ] Completing hard-links part files into the object, so object and upload share storage until the upload directory is discarded; on filesystems without hard links it falls back to a full copy.
- [ ] The collector walks every bucket on every pass (O(objects)); fine for modest stores, needs an incremental scheme for very large ones.
- [ ] Multipart state is per-bucket: renaming or moving a bucket is not supported anyway, but an upload cannot outlive its bucket (the collector removes uploads of a vanished bucket at once).
- [ ] No per-upload or per-user quota on open uploads or total part bytes; an authorised client can fill the disk with parts until `uploadExpiry`.
- [ ] `GET ?partNumber=N` (read one part of a finished object) returns 501.
- [ ] Part checksums (`x-amz-checksum-*`, `x-amz-sdk-checksum-algorithm`) are not verified.

## Phase 9 - encryption at rest: done (see docs/encryption-design.md)
- [x] `internal/kms`: `KMS` interface (GenerateKey, Encrypt, Decrypt, DescribeKey), `local` backend (key file or `NANOIO_KMS_SECRET_KEY`, versioned KEKs), `kes` backend (KES REST over HTTPS, mTLS or API key), TTL + LRU + single-flight cache of unwrapped keys
- [x] `internal/sse`: chunked AES-256-GCM stream (64 KiB chunks, per-stream salt, final-chunk flag, closed-form size arithmetic), key sealing bound to mode and path, per-part keys, sealed plaintext ETag, range decryption by seeking
- [x] SSE-S3, SSE-KMS (with authenticated encryption context) and SSE-C on PUT, GET, HEAD, multipart (per-upload object key, per-part keys), UploadPartCopy and CopyObject; bucket default encryption (`?encryption`); wrong SSE-C key 403, MD5 mismatch 400
- [x] Storage: `UpdateObjectMetadata` (OpSetMeta; conditional on the ETag), `PutOptions.Finalize`, upload metadata from `ListObjectParts`; drain preserves multipart layout
- [x] KEK rotation without re-encrypting data: `nanoio admin rewrap` / `POST /_nanoio/admin/rewrap`
- [x] Threat model in the design doc (section 19)

## Known limitations of encryption at rest
- [ ] **No Vault Transit backend** (KES and `local` only). The `local` backend keeps KEKs beside the data they protect: development only.
- [ ] **Metadata is not encrypted**: object names, sizes (within 16 bytes per 64 KiB chunk), content type, `x-amz-meta-*` and timestamps are readable from a stolen disk. See the threat model.
- [ ] **ListObjects ETags of encrypted single-part objects are the stored (ciphertext) MD5**, not the plaintext MD5 GET returns; `If-Match`/`If-None-Match` accept either. Unsealing in a listing would cost one KMS call per object.
- [ ] **Cross-object CopyObject of an encrypted object re-reads and re-encrypts** the data (MinIO's rule); only self-copy re-wraps without data I/O.
- [ ] **A self-copy in a versioned bucket updates the version in place** (no new version), unlike AWS.
- [ ] **`rewrap` is a full walk** (every version of every key, one KMS call per stale object) with no incremental or scheduled mode, and `kes` does not expose KEK versions, so a KES key rotated inside KES is only detected through a changed key name.
- [ ] **Bucket default encryption** is a document in the reserved bucket `nanoio-sys-config`; another node sees a change within 5 seconds. That bucket name is unavailable to users.
- [ ] Each UploadPart reads the upload's metadata (one extra metadata read per part).
- [ ] A KMS outage fails every PUT/GET of SSE-S3/SSE-KMS objects not served from the key cache; heal, scan and listing are unaffected.
- [ ] `x-amz-checksum-*` of encrypted payloads is still not verified; compression is not implemented (and must precede encryption when it is).
- [ ] No rollback protection: an attacker with disk write access can restore an older, consistent version of an object.

## Known limitations of authentication / IAM
- [ ] **No TLS.** Signatures protect integrity and authenticity, not confidentiality; put a TLS-terminating proxy in front for anything but loopback. `aws:SecureTransport` is therefore always `false`.
- [ ] **IAM changes need a restart** (no SIGHUP reload, no admin API). Add atomic reload.
- [ ] **No groups, bucket policies, ACLs, STS/temporary credentials, or anonymous (public) access.** Policies attach to users only. `X-Amz-Security-Token` is refused (`InvalidToken`).
- [ ] **Policy language subset**: actions must be `s3:*`; condition operators are String(Not)Equals / (Not)Like / EqualsIgnoreCase, Bool, (Not)IpAddress and Numeric*; no `IfExists`, `ForAllValues`, date operators or `aws:CurrentTime`. Only `${aws:username}` (the access key) is a policy variable. Unsupported constructs are rejected at load, never ignored.
- [ ] Condition keys provided: `aws:SourceIp` (TCP peer; `X-Forwarded-For` is deliberately not trusted), `aws:SecureTransport`, `aws:username`, `s3:prefix`, `s3:delimiter`, `s3:max-keys`.
- [ ] SigV2 (header and presigned) is refused with a clear message, which includes `aws` CLI v1's default presign. Use `aws configure set default.s3.signature_version s3v4`. SigV4A (ECDSA) is unsupported.
- [ ] No lockout or rate limiting on repeated bad signatures.
- [ ] Secrets are stored in clear (SigV4 needs the raw key); the IAM and config files warn if group/other readable. Consider encrypting at rest.
- [ ] Unsupported subresources (`?acl`, `?tagging`, ...) are refused with 501 after authentication but are not authorised against an action.
- [ ] S3's "403 instead of 404 without s3:ListBucket" behaviour is not reproduced; denied callers always get 403, permitted ones get 404 for missing keys.
- [ ] Signed streaming chunks are buffered whole and capped at 16 MiB each.
- [ ] `x-amz-checksum-*` headers and trailers are accepted but still not verified.

## Known limitations of the Phase 1 `fs` backend
- [ ] **Listing is O(matching keys)**: every matching key is collected and sorted before paging. Needs a streaming merge-walk.
- [ ] **Case- and normalisation-insensitive filesystems** (macOS APFS default) fold keys `A`/`a`. Use a case-sensitive volume for real data; detect and refuse at startup.
- [ ] **Writers can starve** under a continuous stream of readers on one key (`nslock` has no queue fairness).
- [ ] `fs` does not hash content on read; bitrot detection arrives with `xl`. Size is checked.
- [ ] A `GetObject` reader is not tracked by `Close()`; it keeps its own file handle.
- [ ] Unix only (flock, POSIX rename semantics). Windows is out of scope.
- [ ] Virtual-host style only matches the configured `domains`; there is no Host-header fallback guessing.
- [ ] Single `Owner` placeholder (`nanoio`) in listings until IAM exists.

## Explicit `ErrNotImplemented` sites in `fs`, surfaced by the API as 501 `NotImplemented`
- [ ] `StorageAPI.CopyObject` (the API implements CopyObject without it)
- [ ] Object/bucket subresources: `?acl`, `?tagging`, `?policy`, `?lifecycle`, `?cors`, ... (full list in `internal/api/api.go`)
- [ ] `GET ?list-type=2` is the only list-type accepted; `ListObjectsV2` `Delimiter` is a literal string match like S3

## Later
- [ ] `internal/storage/xl`: Reed-Solomon, bitrot, healing (dependency decision in its design doc)
- [ ] distributed lock manager behind `storage.Locker`
- [ ] `internal/iam`: users, groups, policies
- [ ] `internal/bucket`: bucket config, lifecycle
- [ ] `internal/event`: webhook, then kafka/amqp targets (dependency decision in design doc)
