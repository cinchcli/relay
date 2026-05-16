package relay

import (
	"strings"
	"testing"
)

func TestApplyBootstrapInvite_NoUsers_InstallsInvite(t *testing.T) {
	s := newTestStore(t)
	logBuf := &strings.Builder{}
	if err := ApplyBootstrapInvite(s, "cinch_inv_boot", logBuf); err != nil {
		t.Fatal(err)
	}
	if err := s.RedeemInvite(HashInviteCode("cinch_inv_boot")); err != nil {
		t.Fatalf("bootstrap invite should be redeemable: %v", err)
	}
	if !strings.Contains(logBuf.String(), "bootstrap invite installed") {
		t.Fatalf("expected log message, got %q", logBuf.String())
	}
}

func TestApplyBootstrapInvite_UsersExist_NoOp(t *testing.T) {
	s := newTestStore(t)
	_ = s.CreateUser("u")
	logBuf := &strings.Builder{}
	if err := ApplyBootstrapInvite(s, "cinch_inv_late", logBuf); err != nil {
		t.Fatal(err)
	}
	if err := s.RedeemInvite(HashInviteCode("cinch_inv_late")); err == nil {
		t.Fatal("bootstrap invite should NOT have been installed after users exist")
	}
	if !strings.Contains(logBuf.String(), "ignored") {
		t.Fatalf("expected ignore log, got %q", logBuf.String())
	}
}

func TestApplyBootstrapInvite_DuplicateKey_Idempotent(t *testing.T) {
	s := newTestStore(t)
	code := "cinch_inv_restart"
	logBuf := &strings.Builder{}

	// First call: installs the invite.
	if err := ApplyBootstrapInvite(s, code, logBuf); err != nil {
		t.Fatalf("first call: %v", err)
	}

	// Second call (simulating a relay restart before the invite was
	// redeemed): the row exists, CreateInvite returns a duplicate-key
	// error, but ApplyBootstrapInvite should swallow it and return nil.
	logBuf.Reset()
	if err := ApplyBootstrapInvite(s, code, logBuf); err != nil {
		t.Fatalf("second call: %v", err)
	}
	if !strings.Contains(logBuf.String(), "already present") {
		t.Fatalf("expected 'already present' log, got %q", logBuf.String())
	}

	// The invite should still be redeemable.
	if err := s.RedeemInvite(HashInviteCode(code)); err != nil {
		t.Fatalf("invite should still be redeemable: %v", err)
	}
}
