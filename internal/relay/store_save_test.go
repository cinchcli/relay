package relay

import (
	"testing"
	"time"

	cinchv1 "github.com/cinchcli/cinch-core/go/cinch/v1"
)

// seedSaveClipUser creates a user row so SaveClip's FK constraint is satisfied.
func seedSaveClipUser(t *testing.T, s *Store) string {
	t.Helper()
	userID := "user-saveclip-" + time.Now().UTC().Format("150405.000000000")
	if err := s.CreateUser(userID); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return userID
}

func TestSaveClipHonorsClientCreatedAtInsideWindow(t *testing.T) {
	s := newTestStore(t)
	userID := seedSaveClipUser(t, s)
	captureTime := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	ct := captureTime.Format(time.RFC3339)
	req := &cinchv1.PushClipRequest{
		Content:         "cipher",
		ContentType:     "text",
		Source:          "remote:host",
		ByteSize:        6,
		Encrypted:       true,
		ClientCreatedAt: &ct,
	}
	clip, err := s.SaveClip(userID, req)
	if err != nil {
		t.Fatal(err)
	}
	got, err := time.Parse(time.RFC3339, clip.CreatedAt)
	if err != nil {
		t.Fatalf("parse clip.CreatedAt: %v", err)
	}
	if !got.Equal(captureTime) {
		t.Fatalf("expected %v, got %v", captureTime, got)
	}
}

func TestSaveClipRejectsClientCreatedAtOutsideWindow(t *testing.T) {
	s := newTestStore(t)
	userID := seedSaveClipUser(t, s)
	farPast := time.Now().UTC().Add(-100 * 24 * time.Hour).Format(time.RFC3339)
	req := &cinchv1.PushClipRequest{
		Content:         "x",
		ContentType:     "text",
		Source:          "s",
		ByteSize:        1,
		Encrypted:       true,
		ClientCreatedAt: &farPast,
	}
	before := time.Now().UTC().Add(-1 * time.Second)
	clip, err := s.SaveClip(userID, req)
	if err != nil {
		t.Fatal(err)
	}
	got, err := time.Parse(time.RFC3339, clip.CreatedAt)
	if err != nil {
		t.Fatalf("parse clip.CreatedAt: %v", err)
	}
	if got.Before(before) {
		t.Fatalf("out-of-window timestamp should fall back to NOW(), got %v (before %v)", got, before)
	}
}

func TestSaveClipFallsBackOnMissingClientCreatedAt(t *testing.T) {
	s := newTestStore(t)
	userID := seedSaveClipUser(t, s)
	req := &cinchv1.PushClipRequest{
		Content:     "y",
		ContentType: "text",
		Source:      "s",
		ByteSize:    1,
		Encrypted:   true,
	}
	before := time.Now().UTC().Add(-1 * time.Second)
	clip, err := s.SaveClip(userID, req)
	if err != nil {
		t.Fatal(err)
	}
	got, err := time.Parse(time.RFC3339, clip.CreatedAt)
	if err != nil {
		t.Fatalf("parse clip.CreatedAt: %v", err)
	}
	if got.Before(before) {
		t.Fatalf("missing client_created_at should yield NOW(), got %v (before %v)", got, before)
	}
}
