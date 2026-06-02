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

// Config selects and parameterizes a media backend. It is populated once from
// the environment (LoadConfigFromEnv) by the server entrypoint and passed to
// NewStoreFromConfig, so the MEDIA_* variables are read in exactly one place.
type Config struct {
	Backend  string // "local" (default) | "s3"
	LocalDir string // local backend directory (default "media")
	S3       S3Config
}

// LoadConfigFromEnv reads the MEDIA_* environment variables. Documented in
// README.md. Backend defaults to "local"; UseSSL defaults to true.
func LoadConfigFromEnv() Config {
	return Config{
		Backend:  os.Getenv("MEDIA_BACKEND"),
		LocalDir: os.Getenv("MEDIA_LOCAL_DIR"),
		S3: S3Config{
			Endpoint:  os.Getenv("MEDIA_ENDPOINT"),
			Bucket:    os.Getenv("MEDIA_BUCKET"),
			Region:    os.Getenv("MEDIA_REGION"),
			AccessKey: os.Getenv("MEDIA_ACCESS_KEY_ID"),
			SecretKey: os.Getenv("MEDIA_SECRET_ACCESS_KEY"),
			UseSSL:    os.Getenv("MEDIA_USE_SSL") != "false",
		},
	}
}

// BackendName returns the effective backend name ("local" when unset), for
// startup logging without re-reading the environment.
func (c Config) BackendName() string {
	if c.Backend == "" {
		return "local"
	}
	return c.Backend
}

// NewStore constructs a Store from environment variables. Kept for callers and
// tests that have no Config; equivalent to NewStoreFromConfig(LoadConfigFromEnv()).
//
//	MEDIA_BACKEND — "local" (default) | "s3"
//
// Backend-specific env vars are documented in README.md.
func NewStore() (Store, error) {
	return NewStoreFromConfig(LoadConfigFromEnv())
}

// NewStoreFromConfig constructs a Store from a parsed Config.
func NewStoreFromConfig(cfg Config) (Store, error) {
	switch cfg.BackendName() {
	case "local":
		dir := cfg.LocalDir
		if dir == "" {
			dir = "media"
		}
		return NewLocalStore(dir)
	case "s3":
		return NewS3CompatStore(cfg.S3)
	default:
		return nil, fmt.Errorf("media: unknown MEDIA_BACKEND %q — supported: local, s3", cfg.Backend)
	}
}
