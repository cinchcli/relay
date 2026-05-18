package relay

import (
	"context"
	"testing"
	"time"
)

// insertTestDevice inserts a minimal device row and returns its id.
// Mirrors the raw-insert pattern used by other tests in store_test.go.
func insertTestDevice(t *testing.T, store *Store, userID, hostname, sourceKey string) string {
	t.Helper()
	id := "dev_test_" + hostname
	_, err := store.db.ExecContext(context.Background(),
		`INSERT INTO devices (id, user_id, hostname, source_key) VALUES ($1, $2, $3, $4)`,
		id, userID, hostname, sourceKey,
	)
	if err != nil {
		t.Fatalf("insert device: %v", err)
	}
	return id
}

func TestUpdateDeviceVersion_Upsert(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	userID := "user-version-upsert"
	if err := store.CreateUser(userID); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	devID := insertTestDevice(t, store, userID, "host", "remote:host")

	before := time.Now().UTC()

	if err := store.UpdateDeviceVersion(ctx, devID, "0.1.5", "cli"); err != nil {
		t.Fatalf("first update: %v", err)
	}
	v, ty, ts1, err := store.GetDeviceVersion(ctx, devID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if v != "0.1.5" || ty != "cli" {
		t.Errorf("first read: got (%q, %q), want (%q, %q)", v, ty, "0.1.5", "cli")
	}
	if ts1.Before(before) {
		t.Errorf("first read: timestamp %v is before update start %v", ts1, before)
	}

	time.Sleep(10 * time.Millisecond) // ensure timestamp differs
	if err := store.UpdateDeviceVersion(ctx, devID, "0.1.8", "cli"); err != nil {
		t.Fatalf("second update: %v", err)
	}
	v, ty, ts2, err := store.GetDeviceVersion(ctx, devID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if v != "0.1.8" || ty != "cli" {
		t.Errorf("second read: got (%q, %q), want (%q, %q)", v, ty, "0.1.8", "cli")
	}
	if !ts2.After(ts1) {
		t.Errorf("second read: timestamp %v should be after first %v", ts2, ts1)
	}
}

func TestUpdateDeviceVersion_InvalidType_Rejected(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	userID := "user-version-invalid"
	if err := store.CreateUser(userID); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	devID := insertTestDevice(t, store, userID, "host2", "remote:host2")

	err := store.UpdateDeviceVersion(ctx, devID, "0.1.5", "chrome")
	if err == nil {
		t.Fatal("expected error for invalid client_type, got nil")
	}

	v, ty, ts, getErr := store.GetDeviceVersion(ctx, devID)
	if getErr != nil {
		t.Fatalf("get: %v", getErr)
	}
	if v != "" || ty != "" {
		t.Errorf("columns should be untouched, got (%q, %q)", v, ty)
	}
	if !ts.IsZero() {
		t.Errorf("timestamp should be zero, got %v", ts)
	}
}

func TestUpdateDeviceVersion_AcceptsDesktop(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	userID := "user-version-desktop"
	if err := store.CreateUser(userID); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	devID := insertTestDevice(t, store, userID, "host3", "remote:host3")

	if err := store.UpdateDeviceVersion(ctx, devID, "0.1.7", "desktop"); err != nil {
		t.Fatalf("desktop update: %v", err)
	}
	v, ty, _, err := store.GetDeviceVersion(ctx, devID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if v != "0.1.7" || ty != "desktop" {
		t.Errorf("got (%q, %q), want (%q, %q)", v, ty, "0.1.7", "desktop")
	}
}
