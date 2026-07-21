package bleeplab

import (
	"strings"
	"testing"
)

func TestResolveApplicationReleaseRevision(t *testing.T) {
	priorBuilt := builtReleaseRevision
	t.Cleanup(func() { builtReleaseRevision = priorBuilt })

	t.Run("environment digest", func(t *testing.T) {
		t.Setenv("APPLICATION_RELEASE_REVISION", "sha256:"+strings.Repeat("a", 64))
		builtReleaseRevision = ""
		got, err := resolveApplicationReleaseRevision()
		if err != nil || got != "sha256:"+strings.Repeat("a", 64) {
			t.Fatalf("resolve revision = %q, %v", got, err)
		}
	})

	t.Run("baked revision", func(t *testing.T) {
		t.Setenv("APPLICATION_RELEASE_REVISION", "")
		builtReleaseRevision = strings.Repeat("b", 40)
		got, err := resolveApplicationReleaseRevision()
		if err != nil || got != strings.Repeat("b", 40) {
			t.Fatalf("resolve revision = %q, %v", got, err)
		}
	})

	for _, invalid := range []string{"", "main", "ABCDEF123456", "12345678901", "sha256:abc", "sha256:" + strings.Repeat("g", 64)} {
		t.Run("reject "+invalid, func(t *testing.T) {
			t.Setenv("APPLICATION_RELEASE_REVISION", invalid)
			builtReleaseRevision = ""
			if _, err := resolveApplicationReleaseRevision(); err == nil {
				t.Fatalf("invalid revision %q was accepted", invalid)
			}
		})
	}
}
