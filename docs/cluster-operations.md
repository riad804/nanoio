# NanoIO distributed mode: design contract and operations

This is the contract for the distributed backend (`internal/storage/cluster`,
`internal/cluster/...`). It is written before the code it governs; the tests
named here enforce it.

## Consistency model

* **CP, per object.** Reads and writes of one key are linearizable. When a
  quorum cannot be reached, the operation fails (`503 SlowDown` /
  `ServiceUnavailable`); NanoIO never serves a minority's view.
* **Write quorum** of a set: K drives (K+1 when K == M). **Read quorum**: K
  agreeing drives. Lock quorum: N/2+1 of all nodes exclusive, N/2 shared
  (N even) so that any two conflicting quorums intersect.
* **Locks are leases, the commit is the safety net.** A holder that stalls
  past its lease can act on a lock it no longer holds. Every write is
  therefore also a compare-and-set on the object's generation, checked by
  each drive: at most one writer can reach a write quorum per generation.
* **Indeterminate outcomes.** If a write fails because replies were lost
  or a quorum was missed, it may or may not have taken effect. A later read
  decides; the scanner converges the drives.
* **Not provided:** cross-key transactions or snapshots; a consistent view
  across a LIST that runs while writers are active (each key is individually
  correct); consensus-backed membership; partition tolerance for an even
  split (a 2+2 split of four nodes has no majority and is unavailable on
  both sides, by design).
* **IAM and bucket configuration** are loaded from files on each node and
  are only eventually consistent across nodes (an operator updates them
  everywhere).

## Placement

* A **set** is a fixed group of 2..32 drives, possibly spread over nodes. An
  object's shards are tied to the identity (position) of the drives of its
  set, as in single-node xl.
* A **pool** is a list of sets. Adding a pool is how the cluster grows;
  nothing is rebalanced, existing objects stay where they are.
* Objects of non-draining pools are placed by a consistent-hash ring over
  those pools' sets (128 virtual points per set). Once a cluster has more
  than one pool, a lookup that misses on the ring's set probes the other
  sets in parallel, because an object written before a pool was added is
  not where the new ring would put it. A write of a key that exists in a
  non-draining set updates it in place; a write of a key found only in a
  draining pool goes to the ring's set and the old copy is removed.
* **Leave** is either *decommission* (mark the pool `draining`, restart all
  nodes, run `nanoio admin decommission`; objects are copied to the ring's
  sets and then removed) or *crash and heal* (drives return and the scanner
  repairs them). Drained multipart objects are rewritten as single-part
  objects: their ETag and last-modified time change.

## Cross-set LIST

Every pool and set is asked for one page with the caller's prefix, delimiter,
marker and max-keys. Each set gets its own deadline (`listTimeout`, default
10s).

* The pages are merged in UTF-8 byte order, duplicates (the same key or
  common prefix from several sets) removed keeping the newest object, and
  the result cut to max-keys. `IsTruncated` is true if the merged result
  was cut or any set reported truncation. `NextMarker` is the last name
  returned. Any entry of the true global first page is within its own set's
  first page, so the merge is exact.
* **If a set fails or times out, the LIST fails** with
  `ServiceUnavailable`. A listing is treated as authoritative by sync and
  cleanup tools; a silently incomplete one would make them delete or
  re-upload live data.
* Opt-in `allowPartialList`: the response is the merge of the sets that
  answered, marked incomplete (`x-nanoio-list-incomplete: true`), with the
  failed sets named in the node's log. Off by default.

## Endpoints (all under the reserved `/_nanoio/` namespace)

| Path | Auth | Meaning |
|------|------|---------|
| `/_nanoio/health/live` | none | process is up; touches no drive |
| `/_nanoio/health/ready` | none | this node can serve: every set has a read quorum of drives and the lock server is past its post-restart quarantine |
| `/_nanoio/health/cluster` | none | counts only, no names: `ok` (everything up), `degraded` (quorums hold), `unavailable` (503) |
| `/_nanoio/rpc/v1/*` | HMAC + TLS | node-to-node |
| `/_nanoio/rpc/v1/admin.*` | HMAC, admin identity only | `nanoio admin status\|scan\|decommission`; a peer node's signature is refused |

No valid bucket name begins with `_`, and the bucket name `cluster` is an
ordinary bucket: only the *path prefix* `/_nanoio/` is reserved, and only in
path-style requests (a virtual-host request for bucket `b` and key
`_nanoio/x` is an object like any other). Heartbeats feed `/health/cluster`
only; they never change placement. (Each remote drive also remembers, for one
or two seconds, whether its last call worked, so a dead node does not cost a
timeout per operation; that is a per-call shortcut, not a placement input.)

## Inter-node security

* Every request is HMAC-SHA256-signed over method, path, query, arguments,
  body hash, sender node ID, timestamp, nonce and key ID, with a per-node key
  derived by HKDF-SHA256 from the cluster secret and the node ID. Requests
  outside ±30s of the receiver's clock, and replayed (node, nonce) pairs, are
  refused. Responses are signed and bound to the request nonce.
* Every node holds the cluster secret, because it must derive its peers'
  keys. The scheme attributes requests to a node and defeats replay and
  cross-node reuse; it does not contain a compromised node.
* **TLS is required** between nodes whenever there is more than one node
  (`--inter-node-tls-required`, default true). The client verifies the
  server certificate against the cluster CA; the RPC endpoints refuse
  requests that did not present a client certificate chaining to that CA. A
  node configured without TLS fails to start rather than fall back.
  `--inter-node-tls-required=false` is for development clusters only and
  logs a warning on every start.

### Rotating the cluster secret

`secrets` is an ordered list: the first signs, all verify. Rotation needs
two rolling restarts and an overlap, so the cluster never stops:

1. **Add**: on every node set `secrets: [OLD, NEW]` (OLD still signs; NEW is
   accepted). Restart nodes one at a time. During this phase every node can
   verify both.
2. **Promote**: on every node set `secrets: [NEW, OLD]`. Restart one at a
   time. Nodes already promoted sign with NEW and are verified by nodes that
   still sign with OLD because both are in every list.
3. **Retire**: after all nodes run phase 2 and one minute (twice the
   clock-skew window) has passed, set `secrets: [NEW]` and restart one at a
   time.

Never skip phase 1 on any node before starting phase 2 on another: a node
that does not yet know NEW refuses requests signed with it. A secret must be
at least 16 bytes. With environment configuration, `NANOIO_CLUSTER_SECRET`
is the signing secret and `NANOIO_CLUSTER_SECRET_PREVIOUS` (comma separated)
are verify-only.

## Operations notes

* **Cold start.** A lock server grants nothing for one lock TTL (30s) after
  it starts, so a node that restarted cannot grant a lock that conflicts
  with a lease it forgot. Lock-using requests may be refused for up to that
  long after a whole-cluster cold start, and `/health/ready` reports not
  ready until the quarantine ends.
* **Clock skew** above 30s between nodes makes every RPC fail; run NTP.
* **Adding a pool.** Append a pool to the config on every node and restart
  them. The buckets are created on the new sets by the first scan.
* **Even node counts** tolerate fewer failures than the next odd count
  (4 nodes tolerate 1, like 3).

## The Disk contract (what a drive implementation must honour)

`internal/storage/xl/disk.Disk` is the seam between erasure coding and a
drive, local or remote. It is frozen by the `disktest` suite, which `Local`
and `Remote` both pass.

* **Every method takes a context.** A cancelled or expired context aborts the
  call. A remote drive derives its RPC deadline from it (bounded further by
  per-class timeouts). `Shard` and `FileWriter` stay bound to the context
  they were created with. Cleanup that must outlive a cancelled request
  (rollback, finishing a commit, removing a staging area, discarding an
  upload) is run by xl on a detached, time-bounded context.
* **Every error is a `*disk.Error`, outermost.** `errors.Is(err,
  disk.ErrNotFound)` (and `ErrOffline`, `ErrConflict`, `ErrUnformatted`,
  `ErrForeign`, `ErrInUse`, `ErrCorrupted`, `ErrDiskFull`, `ErrCanceled`)
  behaves identically for a local and a remote drive. Context errors match
  `context.Canceled` / `context.DeadlineExceeded` through `Unwrap`; corrupted
  and disk-full also match `storage.ErrCorrupted` / `storage.ErrDiskFull`.
* **Only `Kind` crosses the wire**, as the RPC error code `k<N>`. The client
  rebuilds a bare `*Error{Kind}` with the remote message as its cause text.
  `Kind` values are append-only: never renumber or reuse one
  (`TestKindValuesAreStable` is the tripwire).
