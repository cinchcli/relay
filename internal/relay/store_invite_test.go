package relay

import (
	"testing"
	"time"
)

func TestMigrate_CreatesInvitesTable(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()
	var exists bool
	if err := s.db.QueryRow(`SELECT EXISTS (
		SELECT 1 FROM information_schema.tables WHERE table_name = 'invites'
	)`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("invites table missing after migrate()")
	}
}

func TestMigrate_AddsUserAdminAndDisplayName(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()
	for _, c := range []struct{ col, want string }{
		{"is_admin", "boolean"},
		{"display_name", "text"},
	} {
		var dt string
		err := s.db.QueryRow(`SELECT data_type FROM information_schema.columns
			WHERE table_name = 'users' AND column_name = $1`, c.col).Scan(&dt)
		if err != nil {
			t.Fatalf("users.%s missing: %v", c.col, err)
		}
		if dt != c.want {
			t.Fatalf("users.%s type = %q, want %q", c.col, dt, c.want)
		}
	}
}

func TestCreateAndListInvite(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	hash := HashInviteCode("cinch_inv_test123")
	exp := time.Now().Add(7 * 24 * time.Hour)
	if err := s.CreateInvite(hash, nil, "friend-han", 1, exp); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListInvites()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 invite, got %d", len(list))
	}
	if list[0].Label != "friend-han" || list[0].MaxUses != 1 {
		t.Fatalf("bad invite: %+v", list[0])
	}
}

func TestRedeemInvite_HappyPath(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()
	hash := HashInviteCode("cinch_inv_red")
	if err := s.CreateInvite(hash, nil, "", 1, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.RedeemInvite(hash); err != nil {
		t.Fatalf("first redeem failed: %v", err)
	}
	if err := s.RedeemInvite(hash); err == nil {
		t.Fatal("second redeem should fail (used up)")
	}
}

func TestRedeemInvite_RejectsExpired(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()
	hash := HashInviteCode("cinch_inv_old")
	_ = s.CreateInvite(hash, nil, "", 1, time.Now().Add(-time.Hour))
	if err := s.RedeemInvite(hash); err == nil {
		t.Fatal("expired invite should be rejected")
	}
}

func TestRevokeInvite_StopsRedemption(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()
	hash := HashInviteCode("cinch_inv_revoked")
	_ = s.CreateInvite(hash, nil, "", 5, time.Now().Add(time.Hour))
	if err := s.RevokeInvite(hash); err != nil {
		t.Fatal(err)
	}
	if err := s.RedeemInvite(hash); err == nil {
		t.Fatal("revoked invite should be rejected")
	}
}

func TestUserAdminAndDisplayName(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	uid := "u1"
	if err := s.CreateUser(uid); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserDisplayName(uid, "han"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserAdmin(uid, true); err != nil {
		t.Fatal(err)
	}
	ok, err := s.IsUserAdmin(uid)
	if err != nil || !ok {
		t.Fatalf("IsUserAdmin=%v err=%v want true", ok, err)
	}
	count, err := s.CountUsers()
	if err != nil || count != 1 {
		t.Fatalf("CountUsers=%d err=%v want 1", count, err)
	}
	list, err := s.ListUsers()
	if err != nil || len(list) != 1 || list[0].DisplayName != "han" || !list[0].IsAdmin {
		t.Fatalf("ListUsers bad: %+v err=%v", list, err)
	}
	// Verify DeleteUser handles invites.created_by SET NULL cleanly.
	invHash := HashInviteCode("cinch_inv_fordelete")
	if err := s.CreateInvite(invHash, &uid, "test", 1, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUser(uid); err != nil {
		t.Fatal(err)
	}
	count2, _ := s.CountUsers()
	if count2 != 0 {
		t.Fatalf("DeleteUser failed: count=%d", count2)
	}
	var createdBy *string
	if err := s.db.QueryRow(`SELECT created_by FROM invites WHERE code_hash = $1`, invHash).Scan(&createdBy); err != nil {
		t.Fatalf("invite row should still exist after user delete: %v", err)
	}
	if createdBy != nil {
		t.Fatalf("created_by should be NULL after user delete, got: %v", *createdBy)
	}
}
