package relay

import "net/http"

// realIP extracts the client IP for rate limiting, trusting forwarded headers
// (CF-Connecting-IP / X-Forwarded-For) only from a trusted proxy peer.
func realIP(r *http.Request) string {
	return clientIP(r.RemoteAddr, r.Header)
}
