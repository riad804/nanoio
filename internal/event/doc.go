// Package event delivers bucket notifications.
//
// The pieces, from the request path outwards:
//
//   - Bus (bus.go): in-process pub/sub. The S3 handlers Publish typed
//     events; Publish never blocks and never fails. A subscriber that cannot
//     keep up loses events (counted), the publisher is never slowed.
//   - ReplayLog (replay.go): every event is also appended to a bounded,
//     rotating on-disk log, so a stream consumer can resume from a sequence
//     number after a disconnect or restart.
//   - Config (config.go): the S3 NotificationConfiguration document with
//     prefix, suffix and tag filters, and its matching rules.
//   - Manager (manager.go): subscribes to the bus, matches each event
//     against its bucket's configuration, and puts it on the durable queue
//     of every target it selects. One worker per target sends from that
//     queue in order, with exponential backoff, batching, and a dead-letter
//     queue after a bounded number of attempts.
//   - Target (target.go): the interface a destination implements. The
//     concrete targets live in internal/event/target/*, so a client library
//     never becomes a dependency of this package or of the API layer.
//
// The delivery guarantees are written down in docs/event-design.md.
package event
