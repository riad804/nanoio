package storage

import (
	"fmt"
	"regexp"
)

var versionUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// StoredVersionID converts a version ID from the StorageAPI boundary to the
// form stored in xl.meta: NullVersionID becomes "" (the null version), a
// UUID is kept, anything else is ErrInvalidVersionID. The empty string is
// returned for an empty input as well, so callers must test the input for
// "was a version named" separately.
func StoredVersionID(id string) (string, error) {
	switch {
	case id == "" || id == NullVersionID:
		return "", nil
	case versionUUID.MatchString(id):
		return id, nil
	}
	return "", fmt.Errorf("%w: %q", ErrInvalidVersionID, id)
}

// ReportedVersionID is the version ID shown to clients for a stored one: a
// bucket that never had versioning reports none, otherwise the null version
// is "null".
func ReportedVersionID(state VersioningState, stored string) string {
	switch {
	case state == VersioningUnversioned:
		return ""
	case stored == "":
		return NullVersionID
	}
	return stored
}
