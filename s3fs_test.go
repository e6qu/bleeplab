package bleeplab

import (
	"context"
	"strings"
	"testing"
)

func TestS3FSUsesConfiguredRegion(t *testing.T) {
	fs, err := newS3FS(context.Background(), "", "bleeplab", "state", "eu-west-1")
	if err != nil {
		t.Fatalf("newS3FS: %v", err)
	}
	if got := fs.client.Options().Region; got != "eu-west-1" {
		t.Fatalf("region = %q, want eu-west-1", got)
	}
}

func TestS3FSRequiresRegion(t *testing.T) {
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_CONFIG_FILE", t.TempDir()+"/config")
	_, err := newS3FS(context.Background(), "", "bleeplab", "state", "")
	if err == nil || !strings.Contains(err.Error(), "AWS region is required") {
		t.Fatalf("newS3FS error = %v", err)
	}
}
