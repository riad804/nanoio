# Bucket event notifications (Phase 11)

Packages: `internal/event` (bus, replay log, queue, config, manager),
`internal/event/target/*` (nine destinations), `internal/api/{notification,adminevents,ws}.go`
(S3 and admin surface), `cmd/nanoio/notify.go` (wiring and admin CLI).

## Pipeline

```
S3 handler ──Publish──▶ Bus ──▶ dispatcher ──▶ per-target durable queue ──▶ worker ──▶ Target.Send
                         │                         (disk, ordered)           (retry, batch,
                         ├──▶ replay writer ──▶ replay log (disk, bounded)    dead-letter)
                         └──▶ live streams (admin websocket / NDJSON)
```

### The request path never waits (11a)

* `Publish` takes one mutex, stamps a sequence number, and does a
  **non-blocking** send into each subscriber's buffered channel. It cannot
  fail and cannot block on any I/O, queue, target or configuration read.
* **Backpressure policy: drop, not block.** A subscriber whose buffer is full
  loses the *new* event and counts it (`Subscription.Dropped`). Drop-newest
  keeps a subscriber's stream an ordered prefix, so a consumer that is told
  "dropped N" resumes from its last sequence number via the replay log.
* The only storage read a handler may add is the bucket's notification
  config from the existing 5 s config cache, and only for (a) GET/HEAD, to
  skip building access events nobody wants, and (b) deletes, when a tag
  filter needs the object's tags. Created/removed events do no I/O at all.
* Matching events to targets happens in the dispatcher goroutine, off the
  request path, against the cached bucket configuration.

### Delivery guarantees

| Hop | Guarantee |
|---|---|
| handler → bus → queue | in memory for microseconds to milliseconds. Lost only if the process is **killed** in that window, or the 16384-event dispatch buffer overflows (counted in `dispatchDropped`). A graceful stop drains it. |
| queue → target | **at-least-once, in order.** An entry leaves the queue only after `Send` returned nil. A crash can redeliver the batch in flight (and, since the ack cursor is persisted lazily, a few already-sent ones); it cannot lose a queued event. |
| per object | events for one object reach one target in publish order (single dispatcher, single FIFO per target, one worker; Kafka additionally keys by `bucket/key`). Two *concurrent* requests on one key are published in handler-completion order; consumers can order them by `Sequencer`. |
| across nodes | each node has its own queue; no cross-node ordering. |
| queue full | `queueLimit` (default 100000) reached → new events for that target are dropped and counted (`dropped`). The queue never evicts: what it holds is the oldest undelivered events. |

fsync: the dispatcher syncs each target queue once per batch it routed.

### Retry and dead letter

Per target: batch of up to `batchSize`; on failure retry the same batch with
exponential backoff `retryBase`·2ⁿ capped at `retryMax`, ±20 % jitter, up to
`maxAttempts` (default 10; `-1` = forever, never dead-letter). When a
multi-event batch exhausts its attempts it is delivered **one event at a
time** (each with a fresh budget) so one poison event cannot take its
neighbours; a single event that exhausts its attempts goes to the target's
**dead-letter queue** (bounded by `deadLetterLimit`, oldest evicted) with the
error and attempt count. `POST /_nanoio/admin/notify/requeue?arn=` moves
dead letters back to the tail of the queue (so per-object order is not
preserved across a requeue).

## Replay log (11a)

`<queueDir>/replay/*.seg`: append-only, CRC-framed, rotated by segment; the
oldest segment is deleted when the byte budget (`notify.replayBytes`, default
64 MiB, `-1` disables) is exceeded. It feeds `?since=` on the event stream
and keeps sequence numbers rising across restarts. It is a best-effort
journal (written by a separate goroutine; may lose its oldest events and
anything the bus dropped); the target queues are the durable part.
`ObjectAccessed` events are published (and so journaled) only when a bucket
configuration selects them or a stream is attached, so reads do not flush the
journal.

## Bucket configuration (11b)

`PUT/GET /<bucket>?notification`. Stored (canonical XML) as the `notification`
document of the bucket's config, like policy/CORS, and removed with the
bucket. `<TopicConfiguration>`, `<QueueConfiguration>` and
`<CloudFunctionConfiguration>` are all accepted and equivalent: each names a
target ARN (`arn:minio:sqs:<region>:<id>:<type>`; region may be empty). An
empty configuration removes it. Refusals: unknown ARN or event name,
malformed filter, duplicate Id, and **overlapping rules** (same rule S3
applies: two rules whose event patterns, prefixes, suffixes and tag filters
can all match one event).

Filters: `<S3Key>` prefix/suffix (S3), and `<S3Tag><FilterRule><Name>key</Name>
<Value>v</Value>` — **a NanoIO extension whose XML form is our own choice**
(every listed tag must be present with that value).

Events produced: `ObjectCreated:{Put,Copy,CompleteMultipartUpload}`,
`ObjectRemoved:{Delete,DeleteMarkerCreated}`, `ObjectAccessed:{Get,Head}`.
Accepted in configurations but **never produced yet**: `ObjectCreated:Post`
(no POST-policy upload), `ObjectRestore:*` (no restore),
`LifecycleExpiration:*` (no lifecycle engine). Access events are emitted
after the response was delivered in full; failed and 304/412 requests emit
nothing. Multi-object delete emits one event per key.

Record format is MinIO's (`EventName`, `Key`, `Records[]`, eventName keeps
its `s3:` prefix). Sizes and ETags are the plaintext values for encrypted
objects.

## Targets (11c)

All share `queueLimit batchSize maxAttempts retryBase retryMax timeout
deadLetterLimit`. Configuration lives under `notify.targets.<type>.<id>` in
the config file (secrets: file mode 0600 — the loader warns otherwise).
Invalid configuration stops startup; an unreachable destination does not.

| type | library | formats | confirmation | keys beyond the shared ones |
|---|---|---|---|---|
| webhook | stdlib | – | 2xx | endpoint authToken headers tls |
| kafka | segmentio/kafka-go | – | acks=all by default | brokers topic clientId requiredAcks sasl tls |
| amqp | rabbitmq/amqp091-go | – | publisher confirms, mandatory returns fail | url exchange exchangeType routingKey declare durable autoDeleted internal mandatory deliveryMode tls |
| mqtt | eclipse/paho.mqtt.golang | – | PUBACK (qos 1 default) | broker topic qos clientId username password keepAlive tls |
| nats | nats-io/nats.go | – | server PONG; JetStream ack with `jetstream` | address subject jetstream username password token credentialsFile tls |
| redis | redis/go-redis | namespace (HSET/HDEL), access (RPUSH) | pipeline exec | address key format username password db tls |
| mysql | go-sql-driver/mysql | namespace (upsert/delete), access (insert) | transaction commit | dsn table format createTable tls |
| postgresql | jackc/pgx stdlib | namespace, access | transaction commit | connectionString table format createTable |
| elasticsearch | stdlib net/http | namespace (_id = sha256(bucket/key)), access | `_bulk` item status | url index format username password tls |

Core NATS cannot say whether any subscriber received a message; use
`jetstream` when that matters. MQTT QoS 0 is unacknowledged by definition.

## Admin surface (11d)

All authenticated with the ordinary SigV4 credentials; actions are
`nanoio:ListenEvents`, `nanoio:NotificationStatus`, `nanoio:RequeueNotifications`.

* `GET /_nanoio/admin/events[?since=N&bucket=&prefix=&suffix=&events=a,b]` —
  live stream. A WebSocket if the request carries an upgrade, otherwise
  newline-delimited JSON on a chunked response (`curl -N`, `nanoio admin
  events`). Each frame is the S3 payload plus `"seq"`; `{"type":"dropped",
  "count":n}` reports events this consumer was too slow for. `since=0` replays
  the whole retained journal first; reconnect with the last `seq`.
* `GET /_nanoio/admin/notify/targets[?probe=false]` — per target: online
  (live probe), last error, consecutive failures, queue length/bytes,
  dead-letter length, delivered/failed/retried/dead-lettered/dropped
  counters; plus pipeline counters.
* `GET /_nanoio/admin/notify/dead?arn=&limit=`, `POST .../requeue?arn=`.
* CLI: `nanoio admin events|notify|dead|requeue [--config ...]`.

## Replicated queues (cluster mode)

In cluster mode (`api.Options.EventLocker` set by `cmd/nanoio`) each target's
queue is replicated in the cluster's own storage:

```
dispatcher → local queue (fsync) → shipper → shared object  _events/<type>-<id>/q/<time>-<node>-<n>
                                                    │  (quorum, erasure-coded system bucket)
            lease holder only:  list → get → Send → delete object
```

* The local queue is still the first landing, so the request path and the
  dispatcher are unchanged. A shipper writes it to the shared store in
  batches of up to 256 events and acks the local copy only after the shared
  write succeeded. **If the cluster is below quorum the events simply stay in
  the local queue** (and replicate when quorum returns); `shipFailures` and
  `lastShipError` in the status show it. Nothing is delivered from local
  state during that time, so delivery is also held.
* Exactly one node delivers a target at a time: it holds the cluster
  namespace lock `_events-lease/<type>-<id>` for as long as it runs; the other
  nodes block on it and take over when the holder stops or dies (lock TTL).
  A holder that is partitioned from the lock quorum without noticing could
  overlap with its successor for up to a lease; the result is duplicates, not
  loss.
* Delivery is at-least-once: a crash of the leader redelivers the shared
  object it was working through (up to 256 events).
* Ordering: objects sort by (publish time of first event, node, counter), so
  each node's events stay in order and nodes interleave by clock. Cross-node
  order for one object is therefore only as good as the clocks; consumers
  should use `Sequencer`. An object shipped late (after a partition) is
  delivered when found, possibly after newer ones.
* Dead letters are shared objects (`.../dead/...`) so they survive node loss
  and can be inspected or requeued from any node; local dead letters from
  before replication was enabled are moved over at start.
* The unshipped tail (milliseconds of events) is still only on the origin
  node's disk: losing that disk in that window loses those events.
* fs and xl (single node) keep local queues: there is nobody to replicate to.

## Not done / limits

* No `ListenBucketNotification` (`?events=` long poll, `mc watch`); the admin
  stream covers the use case with a NanoIO-specific URL.
* No ObjectTagging/ACL/retention event names (not requested).
* Single-node (fs/xl) queues are local files.
* TLS settings for MySQL are registered per target; PostgreSQL TLS is
  configured through the connection string.
