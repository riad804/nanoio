# Bucket replication and site replication (Phase 13)

Packages: `internal/replication` (configuration, matching, status keys),
`internal/api/{replication,site,iamadmin}.go` (engine, site membership,
runtime IAM), the version-import path in `internal/storage/{fs,xl}` and
`internal/meta`.

## Replicas keep their identity

Replication copies a version *under its source version ID and
modification time*. Two storage-layer changes make that possible:

* `PutOptions.Import` / `DeleteOptions.ImportMarker` (fs, xl, cluster; the
  `ImportVersions` conformance test): store a version or a delete marker
  with a given ID and time. Importing an ID that already exists changes
  nothing, so a retried replication is harmless. The bucket must be
  versioned.
* **Version order is now by modification time** (then sequence, then
  version ID), not by commit sequence as before. A replica that arrives
  late with an old time therefore lands in the history instead of becoming
  the current version. To keep the old guarantee for ordinary writes, every
  local write takes `max(now, newest version of the key + 1µs)`
  (`meta.File.MonotonicTime`), so within one cluster time order is still
  commit order whatever the nodes' clocks say. *Imported* versions, and
  anything written on a node with a clock far ahead, can still make a later
  local write sort after them; that is the price of cross-site ordering.

## 13a Bucket replication

* `PUT/GET/DELETE /<bucket>?replication` (`s3:PutReplicationConfiguration`,
  `s3:GetReplicationConfiguration`). Rules: `ID`, `Status`, `Priority`
  (unique; required with more than one rule), `Filter` (prefix, tag, and) or
  legacy `<Prefix>`, `DeleteMarkerReplication`,
  `SourceSelectionCriteria/ReplicaModifications`,
  `ExistingObjectReplication`, `Destination/Bucket` (target ARN) and
  `StorageClass`. `DeleteReplication: Enabled` (permanent version deletes)
  is refused: only delete *markers* replicate.
* **Targets.** The destination ARN `arn:minio:replication::<id>:<bucket>`
  names a remote target registered per source bucket with
  `PUT /_nanoio/admin/replication/target?bucket=` (endpoint, bucket, access
  key, secret). Credentials live there, never in the configuration
  document. Registration checks the destination is reachable and has
  **versioning enabled**; `PutBucketReplication` requires versioning
  Enabled on the source, and Suspended is refused afterwards.
* **Status in metadata.** At write time a matching version is stamped
  `PENDING` (aggregate + per-destination map) in its user metadata, i.e. in
  its xl.meta, atomically with the version. Workers set `COMPLETE` or
  `FAILED` per destination; GET/HEAD report `x-amz-replication-status`
  (`PENDING`, `COMPLETED`, `FAILED`, `REPLICA`). The stamp is the source of
  truth: the queue is an optimisation.
* **What replicates.** PUT/POST/copy/multipart completion (plaintext of
  SSE-S3/KMS objects, read through tiers; SSE-C fails), delete markers,
  and tags / retention / legal hold as metadata updates of the same
  version. Not: permanent version deletes, ACLs, notification config.
* **Queue.** A durable queue per (bucket, priority) under
  `<sys>/replication`; workers (default 4/node) always drain the highest
  priority first; a failed task is requeued behind the others with
  exponential backoff (5s doubling to 10m) and after 8 attempts the version
  is marked `FAILED`. Because `PENDING` is in the object, a scan (startup,
  then every 10 min, one node per bucket) re-queues anything the queue lost
  — including the tasks of a node that died.
* **Loop prevention.** Replica writes carry signed headers
  (`x-amz-nanoio-replication`, source cluster, source version ID and
  time), require `s3:ReplicateObject`, and are stored with status
  `REPLICA` and the source cluster ID. The destination never enqueues a
  request that carries them, and never replicates a REPLICA's data. Only a
  *metadata* change made to a replica goes back, and only under a rule with
  `ReplicaModifications` Enabled.
* **Existing objects / resync.** `ExistingObjectReplication: Enabled`
  triggers a backfill when the configuration is stored. `POST
  /_nanoio/admin/replication/resync?bucket=&arn=&force=` is `mc replicate
  resync`: re-scan, mark every version a rule selects that is not COMPLETE
  `PENDING`, re-send every delete marker (idempotent), and with `force`
  re-send COMPLETE ones too. Progress: `GET .../resync?bucket=`.
* **Metrics.** `GET /_nanoio/admin/replication/metrics[?bucket=]`: per
  destination `queued`, `enqueued`, `completed`, `failed`, `retried`,
  bytes, average and maximum latency (enqueue to acknowledgement). Counters
  are per node and reset at restart; `queued` reflects the node's queues.
* **Conflicts (active-active).** Both sides keep every version; the
  current one is the greatest `(ModTime, VersionID)`. A concurrent
  overwrite on both sides therefore keeps both versions and the later
  write wins everywhere — last-writer-wins by wall clock. A delete marker
  and a write racing resolve the same way.

## Runtime IAM

The IAM file seeds the store and stays authoritative for the names it
defines; users, groups (new: members + policies, a disabled group
contributes nothing, Deny wins) and policies created through
`/_nanoio/admin/iam/{user,group,policy}` are documents in the system bucket
(`_iam/...`) and reload on every node within ~2 s of a change. Secret keys
are stored in clear (as in the IAM file). Policies may now name `nanoio:*`
admin actions to delegate them.

## 13b Site replication

`POST /_nanoio/admin/site/add` (root; body `{self:{name,endpoint},
site:{name,endpoint,accessKey,secretKey}}`) joins another site, which must
be empty (no buckets, no runtime IAM) unless `force`. Then:

* **Handshake and peer auth.** The new site's admin credential is used once.
  Each site issues, for each peer, a dedicated service account
  `nanoio-site-<peerID>` with a random secret and the policy
  `nanoio-site-replicator` (`s3:*` and `nanoio:SiteReplicate`), and the
  peer stores it. Every pair of sites ends up with two such credentials
  (one per direction); adding site C to a group {A,B} makes A, B and C
  introduce themselves to each other. The service account can replicate and
  apply site changes; it cannot manage IAM, tiers or membership (tests).
  Use TLS between sites: the credentials cross the wire on join.
* **What is replicated:** IAM users, groups and policies (not the
  service accounts); buckets (create, delete, versioning, object-lock
  default); bucket policy, ACL, CORS, tags, encryption and lifecycle
  documents; and objects, by automatically configuring a remote target and
  a replication rule (delete markers, replica modifications, existing
  objects) from every site bucket to every peer. Not replicated: tiers,
  notification configuration and targets, KMS keys, batch jobs, the IAM
  file itself.
* **Buckets of a group are always versioned** (a client creating a bucket
  gets versioning enabled; Suspended is refused).
* **Change delivery.** Every local change is stamped `(time, origin site)`,
  queued durably per peer and POSTed to `site/apply`. A receiver applies a
  change only if its stamp beats the stored one (later time, then larger
  origin ID) and does not forward it. Deletions are tombstones.
* **Anti-entropy.** Every 10 s (and soon after bucket changes) one node per
  peer fetches the peer's entity stamps and pushes whatever it has that is
  newer or missing; blocked bucket deletions are retried. This is what
  heals a partition and a lost queue.

### Split brain: what happens and how to recover

Site replication is **asynchronous and multi-master with last-writer-wins
per entity**. There is no quorum and no leader. Consequences:

1. *During a partition each side keeps accepting changes.* Objects are
   safe (versions merge by ID). IAM entries and bucket configuration
   documents are replaced whole: if both sides changed the same user,
   policy document or bucket configuration, **one side's change is
   discarded** when the partition heals — the one with the later stamp,
   which is the later wall-clock time on the node that made it. The loser
   is not merged; it is recorded in `GET /_nanoio/admin/site/status` under
   `conflicts` (last 100, in memory) and logged at WARN.
2. *Clock skew decides ties.* A site whose clock runs ahead wins
   conflicts it should lose and can overwrite a correct newer change
   made elsewhere. Run NTP; the stamp is not a hybrid logical clock.
3. *Create/delete races.* A bucket deleted on one site while the other
   site still holds objects in it is deleted only where it is empty: the
   other site keeps the bucket and its stamp says "deleted", the delete is
   retried every pass, and objects written there meanwhile cannot replicate
   (the peers have no such bucket) and end up `FAILED`. Nothing resurrects
   the bucket by itself. To keep it, create the bucket again on any site
   (the new stamp wins everywhere) and run `replicate-resync`; to drop it,
   empty it on the surviving site and the pending delete completes.
4. *Deletes are not undone by stale copies* (tombstones win by stamp), but
   a user deleted on A and re-created on B later comes back everywhere.
5. *Credential rotation can lock out peers* if a site's service account is
   changed by hand; remove and re-add the site.

Recovery, in order of increasing force:

* **Wait and read the status.** Once the link is back the anti-entropy
  pass converges all sites within a pass or two; check
  `site-status` for `queued: 0` and review `conflicts`.
* **Re-apply what lost.** A change that lost is gone; reissue it on any
  site after convergence (it will be newer and win).
* **Declare one site correct:** on that site run `POST
  /_nanoio/admin/site/resync?authoritative=true` (`nanoio admin site-resync
  --force`): every replicated entity is re-stamped *now* from this site and
  pushed, so this site's state overwrites the others'. Everything the others
  changed since is lost for IAM and bucket configuration; object versions
  are not affected.
* **Remove a site** (`POST site/remove?id=`; on the removed site with no id
  to leave) and re-add it empty (wipe its IAM and buckets, or accept a
  last-writer-wins merge with `force`), when its state is not trusted.

Not solved: there is no automatic detection that two sides diverged, no
three-way merge, and bucket *contents* of a bucket deleted-and-recreated
across the partition are not reconciled beyond version-ID union.

## Limits

* Replica writes of one object are not ordered across the queue's retries;
  convergence relies on time ordering, not delivery order.
* Replication counters reset on restart (the object statuses do not).
* The destination of bucket replication need not be NanoIO, but replica
  imports (`x-amz-nanoio-*`) are understood only by NanoIO; against another
  S3 the version IDs and times differ and PUT is the only supported effect.
* Multipart replicas arrive as single-part objects (ETag differs; the
  source ETag is kept in `x-amz-meta-nanoio-source-etag`).
* Encrypted objects are re-encrypted with the destination bucket's default,
  not the source key; SSE-C objects are not replicated (status `FAILED`).
