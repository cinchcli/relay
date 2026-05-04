package media

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// LocalStore stores media objects on the local filesystem.
// key format: "media/<filename>" — only the base name is used as the filename.
type LocalStore struct {
	dir string
}

// NewLocalStore creates a LocalStore rooted at dir, creating it if needed.
func NewLocalStore(dir string) (*LocalStore, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("media(local): create dir %q: %w", dir, err)
	}
	return &LocalStore{dir: dir}, nil
}

func (s *LocalStore) path(key string) string {
	return filepath.Join(s.dir, filepath.Base(key))
}

func (s *LocalStore) Upload(_ context.Context, key string, r io.Reader, _ int64, _ string) error {
	dst := s.path(key)
	tmp, err := os.CreateTemp(s.dir, "upload-*")
	if err != nil {
		return fmt.Errorf("media(local): create temp: %w", err)
	}
	tmpPath := tmp.Name()

	if _, err := io.Copy(tmp, r); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("media(local): write: %w", err)
	}
	tmp.Close()

	if err := os.Rename(tmpPath, dst); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("media(local): rename: %w", err)
	}
	return nil
}

func (s *LocalStore) Download(_ context.Context, key string) (io.ReadCloser, error) {
	f, err := os.Open(s.path(key))
	if err != nil {
		return nil, fmt.Errorf("media(local): open %q: %w", key, err)
	}
	return f, nil
}

func (s *LocalStore) Delete(_ context.Context, key string) error {
	err := os.Remove(s.path(key))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
