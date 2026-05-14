package relay_test

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"

	relay "github.com/cinchcli/relay/internal/relay"
)

func TestDeriveRelayURL(t *testing.T) {
	t.Run("plain HTTP request returns http://", func(t *testing.T) {
		r := httptest.NewRequest("GET", "http://relay.example.com/demo/session", nil)
		got := relay.DeriveRelayURLForTest(r)
		if want := "http://relay.example.com"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("X-Forwarded-Proto=https returns https://", func(t *testing.T) {
		r := httptest.NewRequest("GET", "http://relay.example.com/demo/session", nil)
		r.Header.Set("X-Forwarded-Proto", "https")
		got := relay.DeriveRelayURLForTest(r)
		if want := "https://relay.example.com"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("CF-Visitor scheme=https returns https://", func(t *testing.T) {
		r := httptest.NewRequest("GET", "http://api.cinchcli.com/demo/session", nil)
		r.Header.Set("CF-Visitor", `{"scheme":"https"}`)
		got := relay.DeriveRelayURLForTest(r)
		if want := "https://api.cinchcli.com"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("CF-Visitor scheme=http stays http://", func(t *testing.T) {
		r := httptest.NewRequest("GET", "http://api.cinchcli.com/demo/session", nil)
		r.Header.Set("CF-Visitor", `{"scheme":"http"}`)
		got := relay.DeriveRelayURLForTest(r)
		if want := "http://api.cinchcli.com"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("direct TLS request returns https://", func(t *testing.T) {
		r := httptest.NewRequest("GET", "https://relay.example.com/demo/session", nil)
		r.TLS = &tls.ConnectionState{}
		got := relay.DeriveRelayURLForTest(r)
		if want := "https://relay.example.com"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("RELAY_PUBLIC_URL overrides everything", func(t *testing.T) {
		t.Setenv("RELAY_PUBLIC_URL", "https://api.cinchcli.com/")
		r := httptest.NewRequest("GET", "http://internal-relay:8090/demo/session", nil)
		got := relay.DeriveRelayURLForTest(r)
		if want := "https://api.cinchcli.com"; got != want {
			t.Errorf("got %q, want %q (trailing slash should be trimmed)", got, want)
		}
	})
}

func TestDeriveWSURL(t *testing.T) {
	t.Run("plain HTTP request returns ws://", func(t *testing.T) {
		r := httptest.NewRequest("GET", "http://relay.example.com/demo/session", nil)
		got := relay.DeriveWSURLForTest(r)
		if want := "ws://relay.example.com/ws"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("X-Forwarded-Proto=https returns wss://", func(t *testing.T) {
		r := httptest.NewRequest("GET", "http://relay.example.com/demo/session", nil)
		r.Header.Set("X-Forwarded-Proto", "https")
		got := relay.DeriveWSURLForTest(r)
		if want := "wss://relay.example.com/ws"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("CF-Visitor scheme=https returns wss://", func(t *testing.T) {
		r := httptest.NewRequest("GET", "http://api.cinchcli.com/demo/session", nil)
		r.Header.Set("CF-Visitor", `{"scheme":"https"}`)
		got := relay.DeriveWSURLForTest(r)
		if want := "wss://api.cinchcli.com/ws"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("RELAY_PUBLIC_WS_URL overrides everything", func(t *testing.T) {
		t.Setenv("RELAY_PUBLIC_WS_URL", "wss://api.cinchcli.com/ws")
		r := httptest.NewRequest("GET", "http://internal-relay:8090/demo/session", nil)
		got := relay.DeriveWSURLForTest(r)
		if want := "wss://api.cinchcli.com/ws"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("RELAY_PUBLIC_URL=https:// derives wss:// for WS", func(t *testing.T) {
		t.Setenv("RELAY_PUBLIC_URL", "https://api.cinchcli.com")
		r := httptest.NewRequest("GET", "http://internal-relay:8090/demo/session", nil)
		got := relay.DeriveWSURLForTest(r)
		if want := "wss://api.cinchcli.com/ws"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("RELAY_PUBLIC_URL=http:// derives ws:// for WS", func(t *testing.T) {
		t.Setenv("RELAY_PUBLIC_URL", "http://internal-relay:8090")
		r := httptest.NewRequest("GET", "http://internal-relay:8090/demo/session", nil)
		got := relay.DeriveWSURLForTest(r)
		if want := "ws://internal-relay:8090/ws"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("RELAY_PUBLIC_WS_URL takes precedence over RELAY_PUBLIC_URL", func(t *testing.T) {
		t.Setenv("RELAY_PUBLIC_URL", "https://wrong.example.com")
		t.Setenv("RELAY_PUBLIC_WS_URL", "wss://right.example.com/ws")
		r := httptest.NewRequest("GET", "http://relay.example.com/demo/session", nil)
		got := relay.DeriveWSURLForTest(r)
		if want := "wss://right.example.com/ws"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
}
