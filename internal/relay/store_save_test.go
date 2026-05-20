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
	clip, _, err := s.SaveClip(userID, req)
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
	clip, _, err := s.SaveClip(userID, req)
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
	clip, _, err := s.SaveClip(userID, req)
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

func TestSaveClipDedupsByIdempotencyKey(t *testing.T) {
	s := newTestStore(t)
	userID := seedSaveClipUser(t, s)
	key := "local-01HXXIDEMP01"
	req := &cinchv1.PushClipRequest{
		Content: "cipher", ContentType: "text", Source: "remote:host",
		ByteSize: 6, Encrypted: true, IdempotencyKey: &key,
	}
	first, isDup1, err := s.SaveClip(userID, req)
	if err != nil {
		t.Fatal(err)
	}
	if isDup1 {
		t.Fatalf("first call should not be marked duplicate")
	}

	second, isDup2, err := s.SaveClip(userID, req)
	if err != nil {
		t.Fatal(err)
	}
	if !isDup2 {
		t.Fatalf("second call with same idempotency_key should be marked duplicate")
	}
	if first.ClipId != second.ClipId {
		t.Fatalf("expected same clip id on retry, got %s vs %s", first.ClipId, second.ClipId)
	}
	if first.CreatedAt != second.CreatedAt {
		t.Fatalf("expected same created_at on retry, got %s vs %s", first.CreatedAt, second.CreatedAt)
	}

	var n int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM clips WHERE user_id=$1", userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 clip row, got %d", n)
	}
}

func TestSaveClipWithoutIdempotencyKeyInsertsEachTime(t *testing.T) {
	s := newTestStore(t)
	userID := seedSaveClipUser(t, s)
	req := &cinchv1.PushClipRequest{
		Content: "x", ContentType: "text", Source: "s", ByteSize: 1, Encrypted: true,
	}
	a, isDupA, err := s.SaveClip(userID, req)
	if err != nil {
		t.Fatal(err)
	}
	if isDupA {
		t.Fatal("nil idempotency_key should never be marked duplicate")
	}
	b, isDupB, err := s.SaveClip(userID, req)
	if err != nil {
		t.Fatal(err)
	}
	if isDupB {
		t.Fatal("nil idempotency_key second call should also not be marked duplicate")
	}
	if a.ClipId == b.ClipId {
		t.Fatal("two nil-key inserts should produce distinct rows")
	}
}

func TestSaveClipDifferentKeysAreDistinct(t *testing.T) {
	s := newTestStore(t)
	userID := seedSaveClipUser(t, s)
	k1 := "local-A"
	k2 := "local-B"
	req1 := &cinchv1.PushClipRequest{Content: "1", ContentType: "text", Source: "s", ByteSize: 1, Encrypted: true, IdempotencyKey: &k1}
	req2 := &cinchv1.PushClipRequest{Content: "2", ContentType: "text", Source: "s", ByteSize: 1, Encrypted: true, IdempotencyKey: &k2}
	a, _, err := s.SaveClip(userID, req1)
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := s.SaveClip(userID, req2)
	if err != nil {
		t.Fatal(err)
	}
	if a.ClipId == b.ClipId {
		t.Fatal("different keys must yield distinct clip ids")
	}
}
