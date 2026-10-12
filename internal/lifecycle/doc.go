// Package lifecycle implements S3 bucket lifecycle management: the
// configuration document (rules with filters and expiration, noncurrent
// version, transition and multipart-abort actions), the evaluator that
// decides what a rule set does to one object version at a given instant,
// and the scanner that applies those decisions across a bucket.
//
// Time is injected (Clock) everywhere a decision depends on "now", so a
// test can verify "expire after 30 days" by moving a fake clock instead of
// waiting. The package reads and changes objects only through
// storage.StorageAPI and reports what it did through a callback; it knows
// nothing of HTTP or of event delivery.
package lifecycle
