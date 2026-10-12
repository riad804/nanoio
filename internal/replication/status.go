package replication

import "strings"

// Object metadata keys. They live in the version's user-defined map (and so
// in its xl.meta), under the reserved internal prefix: copies and clients
// never see or carry them.
const (
	// StatusKey holds the aggregate replication status of a version.
	StatusKey = "x-nanoio-internal-replication-status"
	// TargetsKey holds a JSON object of destination ARN -> status.
	TargetsKey = "x-nanoio-internal-replication-targets"
	// SourceKey holds the ID of the cluster a REPLICA came from.
	SourceKey = "x-nanoio-internal-replication-source"
)

// Statuses.
const (
	StatusPending  = "PENDING"
	StatusComplete = "COMPLETE"
	StatusFailed   = "FAILED"
	// StatusReplica marks a version that arrived by replication; it is what
	// stops it being replicated back.
	StatusReplica = "REPLICA"
)

// Headers of a replicated write. They are x-amz-* so the request signature
// covers them: a replica write that was tampered with in flight fails to
// verify.
const (
	HdrRequest   = "x-amz-nanoio-replication"
	HdrSource    = "x-amz-nanoio-source-cluster"
	HdrVersionID = "x-amz-nanoio-source-version-id"
	HdrModTime   = "x-amz-nanoio-source-mtime"
	HdrSourceTag = "x-amz-meta-nanoio-source-etag"
)

// ClientStatus is what x-amz-replication-status shows for a stored status.
func ClientStatus(s string) string {
	switch s {
	case StatusComplete:
		return "COMPLETED"
	case "":
		return ""
	}
	return s
}

// ARN builds a remote-target ARN.
func ARN(targetID, bucket string) string {
	return "arn:minio:replication::" + targetID + ":" + bucket
}

// ParseARN splits a remote-target ARN into its target ID and bucket.
func ParseARN(arn string) (targetID, bucket string, ok bool) {
	rest, found := strings.CutPrefix(arn, "arn:minio:replication::")
	if !found {
		return "", "", false
	}
	id, b, found := strings.Cut(rest, ":")
	if !found || id == "" || b == "" {
		return "", "", false
	}
	return id, b, true
}

// Aggregate combines per-target statuses: pending while any is pending,
// else failed if any failed, else complete.
func Aggregate(targets map[string]string) string {
	if len(targets) == 0 {
		return ""
	}
	failed := false
	for _, s := range targets {
		switch s {
		case StatusPending:
			return StatusPending
		case StatusFailed:
			failed = true
		}
	}
	if failed {
		return StatusFailed
	}
	return StatusComplete
}
