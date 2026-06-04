package relay

import "net/http"

// SecurityHeaders wraps the whole mux so every response — REST, Connect-RPC,
// the OAuth HTML pages, and the catch-all 404 alike — carries a baseline set of
// hardening headers. The relay otherwise has no global middleware seam (the mux
// is handed straight to http.Server), so without this each handler would have
// to set headers individually and new routes would inherit none.
//
// Wired in cmd/relay: srv.Handler = relay.SecurityHeaders(mux).
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// Never let a browser MIME-sniff a JSON/media response into something
		// executable.
		h.Set("X-Content-Type-Options", "nosniff")
		// The API host has no legitimate reason to be framed; the OAuth sign-in
		// pages should not be clickjackable either.
		h.Set("X-Frame-Options", "DENY")
		// Don't leak request URLs (which carry device_codes) via the Referer header.
		h.Set("Referrer-Policy", "no-referrer")
		// HSTS only when the request actually arrived over TLS (direct r.TLS or
		// an edge-forwarded signal), so plain-HTTP health probes and direct-IP
		// access are not pinned to HTTPS.
		if requestIsHTTPS(r) {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}
