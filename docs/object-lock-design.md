# Phase 8 design: S3 Object Lock

Status: **implemented**. Builds on Phase 7 (versioning): lock is a property of
an object *version*.

## Model

Each object version may carry a `meta.Lock`: an optional retention (mode
`GOVERNANCE` or `COMPLIANCE` and an end instant) and an independent legal hold.
Delete markers carry none. A bucket created with object lock is versioned
(`Enabled`) for life and carries an optional default retention (mode + days or
years) applied to new versions that name none.

`xl.meta` files with any lock are written as format 3 (`meta.FormatLocked`). A
build that predates object lock would decode such a file, ignore `lock`, and
drop it on its next rewrite; refusing the file is the only safe behaviour.

## The rule

Two pure functions in `internal/meta/lock.go`; nothing else decides:

| Question | Function | Answer |
|----------|----------|--------|
| May this version be removed or replaced? | `CheckRemove(v, guard)` | legal hold: never. Active COMPLIANCE: never, `guard` is irrelevant. Active GOVERNANCE: only with `guard.BypassGovernance`. Expired or none: yes. |
| May the lock become this? | `CheckLockChange(old, next, guard)` | active COMPLIANCE: only COMPLIANCE with a date at or after the old one. Active GOVERNANCE: extend or strengthen freely; shorten, remove or weaken only with bypass. Expired or none: anything. Legal hold toggles freely. |

`File.ApplyPut`, `ApplyMarker` and `ApplyRemove` take a `Guard` and call
`CheckRemove` on whatever they would drop, so the *mutation functions
themselves* refuse: a caller cannot forget the check. `ApplySetLock` calls
`CheckLockChange`.

`Guard.BypassGovernance` is set by the API layer only when the request carries
`x-amz-bypass-governance-retention: true` **and** the principal is allowed
`s3:BypassGovernanceRetention` on the key. Asking without the permission is
`AccessDenied`, not a silent downgrade. There is no other source of bypass
anywhere: no admin path, no config flag, no "unlock" operation.

## Where it is applied (defence in depth)

1. **Coordinator** (fs backend, or xl under the bucket-shared + key-exclusive
   locks), on the version list a read quorum agrees on: refuses early with
   `ErrObjectLocked`.
2. **Every drive**, in `Local.commitObject`, with the coordinator's `Guard`
   (so drives decide alike): `OpRemove`, `OpPut` over the null version and
   `OpMarker` over the null version return `KindLocked`. Whole-key
   `Disk.DeleteObject` refuses a key holding a protected version.
3. **Forced bucket deletion** scans for protected versions first and refuses.
4. **Heal** republishes whole version lists with each version's `Lock`
   intact. It drops only a version that no read quorum holds, which was never
   acknowledged to a client (as before object lock).

A drive-level refusal that makes the write quorum impossible surfaces as
`ErrObjectLocked` (403), not as "backend unavailable".

## Clock

Expiry is judged at `Guard.Now`, the coordinating node's `time.Now()`, sent to
every drive. A `retain-until-date` that is not strictly in the future is
refused with `InvalidArgument` for both modes (S3 behaviour; the spec asks for
COMPLIANCE). Retention that has ended protects nothing and may be replaced.

## S3 surface

| Request | Notes |
|---------|-------|
| `PUT /b` + `x-amz-bucket-object-lock-enabled: true` | needs `s3:CreateBucket`, `s3:PutBucketObjectLockConfiguration`, `s3:PutBucketVersioning` |
| `PUT/GET /b?object-lock` | default retention only; `ObjectLockEnabled` must be `Enabled`; `GET` on a plain bucket is 404 `ObjectLockConfigurationNotFoundError` |
| `PUT /b/k` + lock headers | needs `s3:PutObjectRetention` / `s3:PutObjectLegalHold` for the headers sent; mode and date together |
| `PUT/GET /b/k?retention[&versionId]` | empty `<Retention/>` removes (governance + bypass only) |
| `PUT/GET /b/k?legal-hold[&versionId]` | `ON` / `OFF` |
| `DELETE /b/k?versionId` on a locked version | **403 AccessDenied** (not 405) |
| `DELETE /b/k` | delete marker, 204; only versions are protected |
| `PUT /b?versioning` Suspended on a lock bucket | 409 `InvalidBucketState` |

## Tests

| Where | What it pins |
|-------|--------------|
| `meta/lock_test.go` | the two rules as tables; the Apply functions refuse by themselves; format 3 round trip |
| `disktest` `ObjectLock`, `BucketSettings` | drive-level refusals over local and remote drives; settings documents |
| `storagetest` `RunObjectLock` | the matrix on fs, xl (4 layouts), distributed xl, cluster; expiry; defaults; multipart; force delete; races |
| `xl/objectlock_test.go` | damage + heal + restart keep the lock; settings convergence; whole-key paths |
| `cluster/objectlock_test.go` | a new pool gets the lock; diverged sets reconcile; version ops route |
| `api/objectlock_test.go` | principals (root, with, without bypass permission) x header x state over HTTP; XML shapes; validation; multi-delete |

## Not solved

See "Known limitations of object lock" in TODO.md. The honest summary:
COMPLIANCE is enforced by the server, not by physics. An operator with disk
access can still edit metadata or delete files; MinIO has the same caveat.
