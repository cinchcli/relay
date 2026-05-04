package media_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"

	"github.com/cinchcli/relay/internal/media"
)

// TestS3CompatStoreRoundtrip is an integration test that requires a live
// S3-compatible endpoint. It is skipped automatically unless MEDIA_BUCKET and
// MEDIA_ENDPOINT are set.
func TestS3CompatStoreRoundtrip(t *testing.T) {
	bucket := os.Getenv("MEDIA_BUCKET")
	endpoint := os.Getenv("MEDIA_ENDPOINT")
	if bucket == "" || endpoint == "" {
		t.Skip("skipping S3CompatStore integration test (set MEDIA_BUCKET and MEDIA_ENDPOINT to enable)")
	}

	s, err := media.NewS3CompatStore(media.S3Config{
		Endpoint:  endpoint,
		Bucket:    bucket,
		Region:    os.Getenv("MEDIA_REGION"),
		AccessKey: os.Getenv("MEDIA_ACCESS_KEY_ID"),
		SecretKey: os.Getenv("MEDIA_SECRET_ACCESS_KEY"),
		UseSSL:    os.Getenv("MEDIA_USE_SSL") != "false",
	})
	if err != nil {
		t.Fatalf("NewS3CompatStore: %v", err)
	}

	ctx := context.Background()
	content := []byte("s3 roundtrip test")
	key := "media/test-roundtrip.txt"

	if err := s.Upload(ctx, key, bytes.NewReader(content), int64(len(content)), "text/plain"); err != nil {
		t.Fatalf("Upload: %v", err)
	}

	rc, err := s.Download(ctx, key)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	defer rc.Close()
	got, _ := io.ReadAll(rc)
	if string(got) != string(content) {
		t.Errorf("content mismatch: got %q want %q", got, content)
	}

	if err := s.Delete(ctx, key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestNewStoreS3BackendMissingBucket(t *testing.T) {
	t.Setenv("MEDIA_BACKEND", "s3")
	t.Setenv("MEDIA_BUCKET", "")
	_, err := media.NewStore()
	if err == nil {
		t.Error("expected error when MEDIA_BUCKET is empty for s3 backend")
	}
}
