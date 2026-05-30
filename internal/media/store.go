// Package media provides a pluggable interface for binary object storage,
// with backends for local disk and S3-compatible stores.
package media

import (
	"context"
	"fmt"
	"io"
	"os"
)

// Store is the interface for binary media object storage.
// All implementations must be safe for concurrent use.
type Store interface {
	// Upload writes r to the store under key.
	// size is a Content-Length hint; pass -1 if unknown.
	Upload(ctx context.Context, key string, r io.Reader, size int64, contentType string) error

	// Download fetches the object at key.
	// The caller must close the returned ReadCloser.
	Download(ctx context.Context, key string) (io.ReadCloser, error)

	// Delete removes the object at key.
	// Returns nil if the key does not exist.
	Delete(ctx context.Context, key string) error

	// HealthCheck verifies the backend is reachable and usable.
	// Called once at startup; should be cheap and non-mutating.
	HealthCheck(ctx context.Context) error
}

// NewStore constructs a Store from environment variables.
//
//	MEDIA_BACKEND — "local" (default) | "s3"
//
// Backend-specific env vars are documented in README.md.
func NewStore() (Store, error) {
	backend := os.Getenv("MEDIA_BACKEND")
	if backend == "" {
		backend = "local"
	}
	switch backend {
	case "local":
		dir := os.Getenv("MEDIA_LOCAL_DIR")
		if dir == "" {
			dir = "media"
		}
		return NewLocalStore(dir)
	case "s3":
		return NewS3CompatStore(S3Config{
			Endpoint:  os.Getenv("MEDIA_ENDPOINT"),
			Bucket:    os.Getenv("MEDIA_BUCKET"),
			Region:    os.Getenv("MEDIA_REGION"),
			AccessKey: os.Getenv("MEDIA_ACCESS_KEY_ID"),
			SecretKey: os.Getenv("MEDIA_SECRET_ACCESS_KEY"),
			UseSSL:    os.Getenv("MEDIA_USE_SSL") != "false",
		})
	default:
		return nil, fmt.Errorf("media: unknown MEDIA_BACKEND %q — supported: local, s3", backend)
	}
}
