package relay_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	relay "github.com/cinchcli/relay/internal/relay"
)

// SecurityHeaders must attach the baseline hardening headers to every response,
// regardless of which inner handler runs. These are safe on JSON, streaming,
// and HTML responses alike for an API-only host.
func TestSecurityHeaders_SetsBaselineHeadersOnEveryResponse(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := relay.SecurityHeaders(next)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/anything", nil)
	h.ServeHTTP(rec, req)

	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "no-referrer",
		"X-Frame-Options":        "DENY",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("header %s = %q, want %q", k, got, v)
		}
	}

	// Without a TLS signal we must NOT emit HSTS — a plain-HTTP health probe or
	// a direct-IP request should not be pinned to HTTPS.
	if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HSTS must be absent on non-HTTPS request, got %q", got)
	}
}

// On an edge-terminated HTTPS request (X-Forwarded-Proto: https) the middleware
// must emit HSTS so browsers refuse later cleartext requests to the API host.
func TestSecurityHeaders_EmitsHSTSOnHTTPS(t *testing.T) {
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	h := relay.SecurityHeaders(next)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/anything", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	h.ServeHTTP(rec, req)

	const want = "max-age=31536000; includeSubDomains"
	if got := rec.Header().Get("Strict-Transport-Security"); got != want {
		t.Errorf("Strict-Transport-Security = %q, want %q", got, want)
	}
}
