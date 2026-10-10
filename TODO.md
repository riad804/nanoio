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
- [ ] **No retries and no hedging in the RPC layer.** A failed call is a failed drive for that operation; one slow node still stalls writes until its per-call deadline (30s metadata, 5min bulk). Needs "return at write quorum, finish the rest in the background" and a real circuit breaker (the 1-2s health window is a shortcut, not that).
- [ ] **Locks have no queue**: contenders retry with jittered backoff, so a stream of readers can starve a writer. A lock server grants nothing for one TTL (30s) after a restart, so a whole-cluster cold start refuses lock-taking requests for that long.
- [ ] **Every node holds the cluster secret** (needed to derive peers' keys). Per-node keys limit replay and cross-node reuse; a compromised node is not contained. Rotation is a manual three-step rolling restart; nothing verifies that every node picked the new secret.
- [ ] **A pool add does not rebalance.** Once there is more than one pool, an object lookup that misses on the ring's set probes every other set (S-1 extra stats for a GET/PUT of a key that does not exist). Drain rewrites multipart objects as single-part (ETag and last-modified change) and refuses while uploads are in progress; marking a pool draining needs a config change and restart on every node.
- [ ] **Generations restart at 1 after delete and re-create**, so a drive that missed the delete and later returns holds an older object under a higher generation until healed (it is outvoted by quorum, then overwritten by heal).
- [ ] **Cross-set LIST costs N pages per page** and inherits xl's O(objects x drives) listing. The strict policy fails a whole listing for one unavailable set; `allowPartialList` trades that for an incomplete, header-marked result.
- [ ] **IAM and bucket configuration are per-node files**, only eventually consistent across nodes by operator action; there is no replicated config store.
- [ ] **Admin API is minimal** (status, scan, decommission) and unauthenticated health reports expose counts only. No metrics endpoint.
- [ ] Tests run nodes in one process over an in-memory network (plus three loopback processes-in-one for TLS); no multi-host, multi-process soak or Jepsen-style run has been done.

## Known limitations of the xl backend
- [ ] **One erasure set, one process.** No pools, no multiple sets, no expansion; the drive list and parity are fixed for the life of the deployment (reordering is detected and refused; changing parity requires a re-encode that is not implemented). Distributed (network) drives are the natural next phase.
- [ ] **Hash choice**: SHA-256 (stdlib, hardware accelerated) instead of HighwayHash/BLAKE2, to avoid another dependency. The algorithm is recorded per object (`checksums[].algorithm`), so another can be added without a format change.
- [ ] **No scheduled deep scrub.** The background scanner is shallow (presence and size); a bit flip in a shard that reads never touch is only found by `Scan(ctx, true)`, which has no admin command or API yet. Add a configurable deep-scrub cadence and an admin endpoint/CLI (`nanoio heal`).
- [ ] **No drive health tracking.** A slow or flapping drive is retried on every operation; a PUT waits for every shard writer, so one stalled drive stalls writes. Needs per-drive timeouts, a circuit breaker, and "return at write quorum, finish the rest in the background".
- [ ] **Unmounted-disk hazard is only partly guarded.** A vanished drive directory is never recreated, but an empty mount point left behind by an unmounted disk looks like a blank replacement and will be formatted and filled on the parent filesystem. Add an optional "must be a mount point" check.
- [ ] Listing reads `xl.meta` from every drive for every key it returns (quorum confirmation), and a scan walks every object: O(objects x drives). Needs a metadata cache or per-drive listing index.
- [ ] Healing re-reads and re-encodes a whole object, not just the damaged blocks.
- [ ] Per-object read repair is queued best-effort (a full queue drops requests; the periodic scan rediscovers them).
- [ ] xl is not versioned and has no CopyObject/UpdateObjectMetadata, exactly like fs.

## Known limitations of multipart / GC
- [ ] **Part limits are checked at completion, as in S3**, so an undersized part is only reported by CompleteMultipartUpload.
- [ ] **`CopyObject` is still not implemented** (`x-amz-copy-source` on a plain PUT returns 501), so `aws s3 cp s3://a s3://b` and `aws s3 mv` fail. UploadPartCopy exists, which is the building block.
- [ ] CompleteMultipartUpload holds the upload, bucket and key locks while linking parts and committing; completion of a 10,000-part upload blocks writers of that one key for that duration. S3's keep-alive whitespace on slow completions is not sent.
- [ ] Completing hard-links part files into the object, so object and upload share storage until the upload directory is discarded; on filesystems without hard links it falls back to a full copy.
- [ ] The collector walks every bucket on every pass (O(objects)); fine for modest stores, needs an incremental scheme for very large ones.
- [ ] Multipart state is per-bucket: renaming or moving a bucket is not supported anyway, but an upload cannot outlive its bucket (the collector removes uploads of a vanished bucket at once).
- [ ] No per-upload or per-user quota on open uploads or total part bytes; an authorised client can fill the disk with parts until `uploadExpiry`.
- [ ] `GET ?partNumber=N` (read one part of a finished object) returns 501.
- [ ] Part checksums (`x-amz-checksum-*`, `x-amz-sdk-checksum-algorithm`) are not verified.

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
- [ ] Versioning: `PutOptions.Versioned`, `DeleteOptions.Versioned` / `VersionID`, `ListObjectVersions`, `?versionId`, `?versioning`, `?versions`
- [ ] `CopyObject` (`x-amz-copy-source`), `UpdateObjectMetadata`
- [ ] Object/bucket subresources: `?acl`, `?tagging`, `?policy`, `?lifecycle`, `?cors`, ... (full list in `internal/api/api.go`)
- [ ] `GET ?list-type=2` is the only list-type accepted; `ListObjectsV2` `Delimiter` is a literal string match like S3

## Later
- [ ] `internal/storage/xl`: Reed-Solomon, bitrot, healing (dependency decision in its design doc)
- [ ] distributed lock manager behind `storage.Locker`
- [ ] `internal/iam`: users, groups, policies
- [ ] `internal/bucket`: bucket config, lifecycle
- [ ] `internal/event`: webhook, then kafka/amqp targets (dependency decision in design doc)
