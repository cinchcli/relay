package relay

import "testing"

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
