package relay

import (
	"strings"
	"testing"
	"time"
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
	_ = time.Now() // keep time import if linter complains
}
