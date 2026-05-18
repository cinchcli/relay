package relay

import (
	"context"
	"testing"

	cinchv1 "github.com/cinchcli/cinch-core/go/cinch/v1"
)

func TestListDevices_IncludesVersionFields(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	userID := "user-list-devices-version"
	if err := store.CreateUser(userID); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	deviceID := insertTestDevice(t, store, userID, "version-host", "remote:version-host")

	if err := store.UpdateDeviceVersion(ctx, deviceID, "0.1.8", "cli"); err != nil {
		t.Fatalf("update version: %v", err)
	}

	devs, err := store.ListDevices(userID)
	if err != nil {
		t.Fatalf("list devices: %v", err)
	}
	var found *cinchv1.Device
	for _, d := range devs {
		if d.Id == deviceID {
			found = d
			break
		}
	}
	if found == nil {
		t.Fatal("device missing from response")
	}

	if got := found.ClientVersion; got == nil || *got != "0.1.8" {
		t.Errorf("client_version = %v, want pointer to 0.1.8", got)
	}
	if got := found.ClientType; got == nil || *got != "cli" {
		t.Errorf("client_type = %v, want pointer to cli", got)
	}
	if found.ClientVersionAt == nil {
		t.Error("client_version_at should be set after update")
	}
}

func TestListDevices_NullVersion_NilFields(t *testing.T) {
	store := newTestStore(t)

	userID := "user-list-devices-null"
	if err := store.CreateUser(userID); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	deviceID := insertTestDevice(t, store, userID, "no-version-host", "remote:no-version-host")

	devs, err := store.ListDevices(userID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var found *cinchv1.Device
	for _, d := range devs {
		if d.Id == deviceID {
			found = d
			break
		}
	}
	if found == nil {
		t.Fatal("device missing")
	}
	if found.ClientVersion != nil {
		t.Errorf("client_version should be nil; got %v", *found.ClientVersion)
	}
	if found.ClientType != nil {
		t.Errorf("client_type should be nil; got %v", *found.ClientType)
	}
	if found.ClientVersionAt != nil {
		t.Errorf("client_version_at should be nil; got %v", *found.ClientVersionAt)
	}
}
