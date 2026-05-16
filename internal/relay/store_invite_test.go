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
