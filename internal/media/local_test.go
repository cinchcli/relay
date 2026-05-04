package media_test

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/cinchcli/relay/internal/media"
)

func TestLocalStoreUploadDownloadDelete(t *testing.T) {
	dir := t.TempDir()
	s, err := media.NewLocalStore(dir)
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}

	ctx := context.Background()
	content := []byte("hello media")
	key := "media/test.png"

	if err := s.Upload(ctx, key, bytes.NewReader(content), int64(len(content)), "image/png"); err != nil {
		t.Fatalf("Upload: %v", err)
	}

	rc, err := s.Download(ctx, key)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	defer rc.Close()
	got, _ := io.ReadAll(rc)
	if string(got) != string(content) {
		t.Errorf("Download content mismatch: got %q want %q", got, content)
	}

	if err := s.Delete(ctx, key); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err = s.Download(ctx, key)
	if err == nil {
		t.Error("expected error downloading deleted key, got nil")
	}
}

func TestLocalStoreDeleteMissingKeyIsNoOp(t *testing.T) {
	dir := t.TempDir()
	s, _ := media.NewLocalStore(dir)
	if err := s.Delete(context.Background(), "media/nonexistent.png"); err != nil {
		t.Errorf("Delete missing key should be no-op, got: %v", err)
	}
}

func TestNewStoreLocalBackend(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MEDIA_BACKEND", "local")
	t.Setenv("MEDIA_LOCAL_DIR", dir)
	s, err := media.NewStore()
	if err != nil {
		t.Fatalf("NewStore(local): %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil store")
	}
}

func TestNewStoreUnknownBackendErrors(t *testing.T) {
	t.Setenv("MEDIA_BACKEND", "bogus")
	_, err := media.NewStore()
	if err == nil {
		t.Error("expected error for unknown MEDIA_BACKEND")
	}
}

