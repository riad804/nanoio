package event

import "strings"

// Event names. A configuration may use any of these, or a "<class>:*"
// wildcard that covers the class.
const (
	ObjectCreatedPut                       = "s3:ObjectCreated:Put"
	ObjectCreatedPost                      = "s3:ObjectCreated:Post"
	ObjectCreatedCopy                      = "s3:ObjectCreated:Copy"
	ObjectCreatedCompleteMultipartUpload   = "s3:ObjectCreated:CompleteMultipartUpload"
	ObjectRemovedDelete                    = "s3:ObjectRemoved:Delete"
	ObjectRemovedDeleteMarkerCreated       = "s3:ObjectRemoved:DeleteMarkerCreated"
	ObjectAccessedGet                      = "s3:ObjectAccessed:Get"
	ObjectAccessedHead                     = "s3:ObjectAccessed:Head"
	ObjectRestorePost                      = "s3:ObjectRestore:Post"
	ObjectRestoreCompleted                 = "s3:ObjectRestore:Completed"
	ObjectRestoreDelete                    = "s3:ObjectRestore:Delete"
	LifecycleExpirationDelete              = "s3:LifecycleExpiration:Delete"
	LifecycleExpirationDeleteMarkerCreated = "s3:LifecycleExpiration:DeleteMarkerCreated"
	// LifecycleTransition is emitted when a lifecycle rule moves an object
	// version's data to a tier.
	LifecycleTransition = "s3:LifecycleTransition"
)

// concreteNames lists every event a configuration can subscribe to, by
// class. NanoIO emits all of them except the Post, Restore and Lifecycle
// ones, which have no producer yet (there is no POST-policy upload, restore,
// or lifecycle engine); configurations may still name them.
var concreteNames = []string{
	ObjectCreatedPut, ObjectCreatedPost, ObjectCreatedCopy, ObjectCreatedCompleteMultipartUpload,
	ObjectRemovedDelete, ObjectRemovedDeleteMarkerCreated,
	ObjectAccessedGet, ObjectAccessedHead,
	ObjectRestorePost, ObjectRestoreCompleted, ObjectRestoreDelete,
	LifecycleExpirationDelete, LifecycleExpirationDeleteMarkerCreated,
	LifecycleTransition,
}

var classes = []string{"s3:ObjectCreated:", "s3:ObjectRemoved:", "s3:ObjectAccessed:", "s3:ObjectRestore:", "s3:LifecycleExpiration:"}

// ValidName reports whether name is a known event name or class wildcard.
func ValidName(name string) bool {
	for _, c := range classes {
		if name == c+"*" {
			return true
		}
	}
	for _, n := range concreteNames {
		if n == name {
			return true
		}
	}
	return false
}

// NameMatches reports whether a configuration's event pattern selects the
// concrete event name.
func NameMatches(pattern, name string) bool {
	if pattern == name {
		return true
	}
	if i := strings.LastIndexByte(pattern, '*'); i == len(pattern)-1 && i > 0 {
		return strings.HasPrefix(name, pattern[:i])
	}
	return false
}

// namesOverlap reports whether two patterns can select a common event.
func namesOverlap(a, b string) bool {
	return NameMatches(a, b) || NameMatches(b, a)
}

// IsRemoval reports whether the event describes a removed object, whose
// tags are no longer readable once the event is produced.
func IsRemoval(name string) bool {
	return strings.HasPrefix(name, "s3:ObjectRemoved:") || strings.HasPrefix(name, "s3:LifecycleExpiration:")
}
