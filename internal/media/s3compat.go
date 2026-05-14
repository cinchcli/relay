package media

import (
	"context"
	"fmt"
	"io"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// S3Config holds configuration for an S3-compatible object store backend.
type S3Config struct {
	Endpoint  string // e.g. "s3.amazonaws.com", "account.r2.cloudflarestorage.com"
	Bucket    string // required
	Region    string // default "us-east-1"
	AccessKey string // leave empty to use IAM instance profile / env chain
	SecretKey string
	UseSSL    bool // default true; set MEDIA_USE_SSL=false for local MinIO
}

// S3CompatStore stores media objects in any S3-compatible object store
// (AWS S3, Cloudflare R2, MinIO, GCS S3-compat, DigitalOcean Spaces, etc.).
type S3CompatStore struct {
	client *minio.Client
	bucket string
}

// NewS3CompatStore creates an S3CompatStore from cfg.
func NewS3CompatStore(cfg S3Config) (*S3CompatStore, error) {
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("media(s3): MEDIA_BUCKET is required")
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = "s3.amazonaws.com"
	}

	var creds *credentials.Credentials
	if cfg.AccessKey != "" && cfg.SecretKey != "" {
		creds = credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, "")
	} else {
		creds = credentials.NewChainCredentials([]credentials.Provider{
			&credentials.EnvAWS{},
			&credentials.IAM{Client: nil},
		})
	}

	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  creds,
		Secure: cfg.UseSSL,
		Region: cfg.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("media(s3): init client: %w", err)
	}

	return &S3CompatStore{client: client, bucket: cfg.Bucket}, nil
}

func (s *S3CompatStore) Upload(ctx context.Context, key string, r io.Reader, size int64, contentType string) error {
	_, err := s.client.PutObject(ctx, s.bucket, key, r, size, minio.PutObjectOptions{
		ContentType: contentType,
	})
	if err != nil {
		return fmt.Errorf("media(s3): upload %q: %w", key, err)
	}
	return nil
}

func (s *S3CompatStore) Download(ctx context.Context, key string) (io.ReadCloser, error) {
	obj, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("media(s3): download %q: %w", key, err)
	}
	// GetObject is lazy — Stat forces the network round-trip so callers get
	// a missing-key error here rather than on the first Read.
	if _, err := obj.Stat(); err != nil {
		obj.Close()
		return nil, fmt.Errorf("media(s3): download %q: %w", key, err)
	}
	return obj, nil
}

func (s *S3CompatStore) Delete(ctx context.Context, key string) error {
	err := s.client.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{})
	if err != nil {
		// S3 returns 204 for missing keys, but some providers return NoSuchKey.
		if minio.ToErrorResponse(err).Code == "NoSuchKey" {
			return nil
		}
		return fmt.Errorf("media(s3): delete %q: %w", key, err)
	}
	return nil
}

func (s *S3CompatStore) HealthCheck(ctx context.Context) error {
	exists, err := s.client.BucketExists(ctx, s.bucket)
	if err != nil {
		return fmt.Errorf("media(s3): bucket %q: %w", s.bucket, err)
	}
	if !exists {
		return fmt.Errorf("media(s3): bucket %q not found or not accessible", s.bucket)
	}
	return nil
}
