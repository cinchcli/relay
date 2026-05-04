package media

import "fmt"

// S3Config holds configuration for an S3-compatible object store backend.
type S3Config struct {
	Endpoint  string // e.g. "s3.amazonaws.com", "account.r2.cloudflarestorage.com"
	Bucket    string // required
	Region    string // default "us-east-1"
	AccessKey string // leave empty to use IAM instance profile / env chain
	SecretKey string
	UseSSL    bool // default true; set MEDIA_USE_SSL=false for local MinIO
}

// NewS3CompatStore is implemented in Task 2 after the minio-go dep is added.
// This stub returns an error until then.
func NewS3CompatStore(cfg S3Config) (Store, error) {
	return nil, fmt.Errorf("media(s3): s3 backend not yet implemented")
}
