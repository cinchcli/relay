package relay

import (
	"net/url"
	"strings"
	"testing"
)

func TestNormalizePostgresDSN_SalvagesRawPassword(t *testing.T) {
	tests := []struct {
		in          string
		wantScheme  string
		wantPass    string
		wantEncoded string
	}{
		{in: "postgres://user:pa/ss@host/db", wantScheme: "postgres", wantPass: "pa/ss", wantEncoded: "pa%2Fss"},
		{in: "postgres://user:pa?ss@host/db", wantScheme: "postgres", wantPass: "pa?ss", wantEncoded: "pa%3Fss"},
		{in: "postgres://user:pa#ss@host/db", wantScheme: "postgres", wantPass: "pa#ss", wantEncoded: "pa%23ss"},
		{in: "postgresql://user:pa/ss@host/db", wantScheme: "postgresql", wantPass: "pa/ss", wantEncoded: "pa%2Fss"},
	}

	for _, tt := range tests {
		out := normalizePostgresDSN(tt.in)
		u, err := url.Parse(out)
		if err != nil {
			t.Fatalf("url.Parse(%q) failed: %v (out=%q)", tt.in, err, out)
		}
		if u.Scheme != tt.wantScheme {
			t.Fatalf("scheme mismatch: got %q want %q (out=%q)", u.Scheme, tt.wantScheme, out)
		}
		if u.User == nil {
			t.Fatalf("missing userinfo (out=%q)", out)
		}
		pass, ok := u.User.Password()
		if !ok {
			t.Fatalf("missing password (out=%q)", out)
		}
		if pass != tt.wantPass {
			t.Fatalf("password mismatch: got %q want %q (out=%q)", pass, tt.wantPass, out)
		}
		if !strings.Contains(out, tt.wantEncoded) {
			t.Fatalf("expected encoded password fragment %q in out=%q", tt.wantEncoded, out)
		}
	}
}

func TestNormalizePostgresDSN_DoesNotDoubleEncode(t *testing.T) {
	in := "postgres://user:p%40ss@host/db"
	out := normalizePostgresDSN(in)
	if out != in {
		t.Fatalf("expected unchanged; got %q want %q", out, in)
	}
}

func TestNormalizePostgresDSN_LeavesKVDSNUntouched(t *testing.T) {
	in := "host=localhost user=relay password=p/ss dbname=relay sslmode=disable"
	out := normalizePostgresDSN(in)
	if out != in {
		t.Fatalf("expected unchanged; got %q want %q", out, in)
	}
}
