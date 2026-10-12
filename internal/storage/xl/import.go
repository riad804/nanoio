package xl

import (
	"errors"
	"fmt"

	"nanoio/internal/storage"
)

// importID validates a replication import against the bucket's state and
// returns the stored version ID.
func importID(state storage.VersioningState, imp *storage.VersionImport) (string, error) {
	if state == storage.VersioningUnversioned {
		return "", fmt.Errorf("%w: replicas need a versioned bucket", storage.ErrInvalidBucketState)
	}
	if imp.ModTime.IsZero() {
		return "", errors.New("an imported version needs its modification time")
	}
	return storage.StoredVersionID(imp.VersionID)
}
