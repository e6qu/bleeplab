package bleeplab

import (
	"fmt"
	"os"
	"strings"
)

// builtReleaseRevision is populated when a release container is built. A
// deployment may override it with the digest of the selected image manifest.
var builtReleaseRevision string

func resolveApplicationReleaseRevision() (string, error) {
	for _, candidate := range []string{os.Getenv("APPLICATION_RELEASE_REVISION"), builtReleaseRevision} {
		revision := strings.TrimSpace(candidate)
		if revision == "" {
			continue
		}
		if !isImmutableReleaseRevision(revision) {
			return "", fmt.Errorf("APPLICATION_RELEASE_REVISION must be a 12-64 character lowercase hexadecimal revision or SHA-256 digest")
		}
		return revision, nil
	}
	return "", fmt.Errorf("APPLICATION_RELEASE_REVISION must identify the immutable deployed Bleeplab release")
}

func isImmutableReleaseRevision(value string) bool {
	if strings.HasPrefix(value, "sha256:") {
		return isLowerHex(strings.TrimPrefix(value, "sha256:"), 64, 64)
	}
	return isLowerHex(value, 12, 64)
}

func isLowerHex(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}
