package relay

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	cinchv1 "github.com/cinchcli/relay/internal/cinchv1"
	"github.com/cinchcli/relay/internal/media"
)

// fakeMediaStore is an in-memory media.Store for testing the
// PushClip → uploadImageMedia routing. Captures every Upload call so
// assertions can inspect the key and bytes the relay tried to write.
type fakeMediaStore struct {
	uploads     map[string][]byte
	uploadErr   error
	uploadCalls int
}

func (f *fakeMediaStore) Upload(_ context.Context, key string, r io.Reader, _ int64, _ string) error {
	f.uploadCalls++
	if f.uploadErr != nil {
		return f.uploadErr
	}
	bs, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	if f.uploads == nil {
		f.uploads = make(map[string][]byte)
	}
	f.uploads[key] = bs
	return nil
}

func (f *fakeMediaStore) Download(_ context.Context, key string) (io.ReadCloser, error) {
	b, ok := f.uploads[key]
	if !ok {
		return nil, errors.New("not found")
	}
	return io.NopCloser(strings.NewReader(string(b))), nil
}

func (f *fakeMediaStore) Delete(_ context.Context, key string) error {
	delete(f.uploads, key)
	return nil
}

func (f *fakeMediaStore) HealthCheck(_ context.Context) error { return nil }

var _ media.Store = (*fakeMediaStore)(nil)

func TestUploadImageMedia_CanonicalImageStampsMediaPath(t *testing.T) {
	ms := &fakeMediaStore{}
	req := &cinchv1.PushClipRequest{
		ContentType: "image",
		Content:     "encrypted-png-blob",
	}

	if err := uploadImageMedia(context.Background(), ms, req); err != nil {
		t.Fatalf("uploadImageMedia: %v", err)
	}

	if ms.uploadCalls != 1 {
		t.Fatalf("expected 1 upload call, got %d", ms.uploadCalls)
	}
	if req.MediaPath == nil || *req.MediaPath == "" {
		t.Fatal("expected MediaPath to be set on the request")
	}
	if !strings.HasPrefix(*req.MediaPath, "clips/") || !strings.HasSuffix(*req.MediaPath, ".bin") {
		t.Errorf("media key shape unexpected: %q", *req.MediaPath)
	}
	if got, want := string(ms.uploads[*req.MediaPath]), "encrypted-png-blob"; got != want {
		t.Errorf("uploaded bytes: got %q want %q", got, want)
	}
	if req.ByteSize != int64(len("encrypted-png-blob")) {
		t.Errorf("ByteSize: got %d want %d", req.ByteSize, len("encrypted-png-blob"))
	}
}

func TestUploadImageMedia_LegacyMimeContentTypeAlsoRoutes(t *testing.T) {
	// Pre-2026-05 desktop builds emitted MIME-style content_types.
	// `strings.HasPrefix(..., "image")` covers both "image" and "image/png".
	ms := &fakeMediaStore{}
	req := &cinchv1.PushClipRequest{
		ContentType: "image/png",
		Content:     "x",
	}

	if err := uploadImageMedia(context.Background(), ms, req); err != nil {
		t.Fatalf("uploadImageMedia: %v", err)
	}
	if ms.uploadCalls != 1 {
		t.Fatalf("expected upload, got %d calls", ms.uploadCalls)
	}
	if req.MediaPath == nil {
		t.Fatal("MediaPath must be set for image/png clips")
	}
}

func TestUploadImageMedia_PreservesInlineContent(t *testing.T) {
	// D1 dual-write: the inline `Content` field stays populated so existing
	// clients that read clips.content keep working. Only D2 will clear it.
	ms := &fakeMediaStore{}
	req := &cinchv1.PushClipRequest{
		ContentType: "image",
		Content:     "stay-put",
	}
	if err := uploadImageMedia(context.Background(), ms, req); err != nil {
		t.Fatalf("uploadImageMedia: %v", err)
	}
	if req.Content != "stay-put" {
		t.Errorf("Content was mutated to %q; D1 must preserve inline content", req.Content)
	}
}

func TestUploadImageMedia_SkipsNonImageContentType(t *testing.T) {
	ms := &fakeMediaStore{}
	req := &cinchv1.PushClipRequest{
		ContentType: "text",
		Content:     "hello",
	}
	if err := uploadImageMedia(context.Background(), ms, req); err != nil {
		t.Fatalf("uploadImageMedia: %v", err)
	}
	if ms.uploadCalls != 0 {
		t.Errorf("text clip must not trigger media upload; got %d calls", ms.uploadCalls)
	}
	if req.MediaPath != nil {
		t.Errorf("text clip must not get a MediaPath, got %q", *req.MediaPath)
	}
}

func TestUploadImageMedia_SkipsWhenNoMediaBackend(t *testing.T) {
	// When MEDIA_BACKEND is unset, m == nil. Image push must fall back to
	// inline-only storage (current behavior) instead of erroring.
	req := &cinchv1.PushClipRequest{
		ContentType: "image",
		Content:     "encrypted",
	}
	if err := uploadImageMedia(context.Background(), nil, req); err != nil {
		t.Fatalf("uploadImageMedia with nil store: %v", err)
	}
	if req.MediaPath != nil {
		t.Errorf("no backend ⇒ MediaPath must remain unset, got %q", *req.MediaPath)
	}
}

func TestUploadImageMedia_SkipsEmptyContent(t *testing.T) {
	ms := &fakeMediaStore{}
	req := &cinchv1.PushClipRequest{
		ContentType: "image",
		Content:     "",
	}
	if err := uploadImageMedia(context.Background(), ms, req); err != nil {
		t.Fatalf("uploadImageMedia: %v", err)
	}
	if ms.uploadCalls != 0 {
		t.Errorf("empty content must not trigger upload; got %d calls", ms.uploadCalls)
	}
	if req.MediaPath != nil {
		t.Errorf("empty content ⇒ no MediaPath, got %q", *req.MediaPath)
	}
}

func TestUploadImageMedia_PropagatesUploadError(t *testing.T) {
	// Upload failures surface to the caller so PushClip can return a
	// CodeInternal — the relay must not silently fall back to inline-only
	// storage when the operator wired a media backend that is misbehaving.
	wantErr := errors.New("s3 unreachable")
	ms := &fakeMediaStore{uploadErr: wantErr}
	req := &cinchv1.PushClipRequest{
		ContentType: "image",
		Content:     "encrypted",
	}
	err := uploadImageMedia(context.Background(), ms, req)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("error not wrapped: %v", err)
	}
	if req.MediaPath != nil {
		t.Errorf("failed upload must leave MediaPath unset, got %q", *req.MediaPath)
	}
}

func TestUploadImageMedia_DoesNotOverwriteExplicitByteSize(t *testing.T) {
	// Callers (e.g. legacy PushBinaryClip) sometimes set ByteSize ahead of
	// SaveClip when the source-of-truth size differs from len(Content).
	// uploadImageMedia must only fill the field when it was zero.
	ms := &fakeMediaStore{}
	req := &cinchv1.PushClipRequest{
		ContentType: "image",
		Content:     "ab", // 2 bytes
		ByteSize:    9999,
	}
	if err := uploadImageMedia(context.Background(), ms, req); err != nil {
		t.Fatalf("uploadImageMedia: %v", err)
	}
	if req.ByteSize != 9999 {
		t.Errorf("ByteSize was overwritten: got %d want 9999", req.ByteSize)
	}
}
