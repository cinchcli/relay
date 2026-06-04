package relay

import (
	"net/http"
	"testing"
)

// Forwarded IP headers are trusted only when the immediate peer is a trusted
// proxy (a Cloudflare edge address, or loopback/private for tests and
// self-host behind a private LB). A directly-connected client must not be able
// to spoof its rate-limit identity via X-Forwarded-For / CF-Connecting-IP.
func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		want       string
	}{
		{
			name:       "cloudflare peer trusts CF-Connecting-IP",
			remoteAddr: "104.16.0.1:443", // within Cloudflare 104.16.0.0/13
			headers:    map[string]string{"CF-Connecting-IP": "203.0.113.7"},
			want:       "203.0.113.7",
		},
		{
			name:       "cloudflare peer falls back to first X-Forwarded-For hop",
			remoteAddr: "172.64.0.5:443", // within Cloudflare 172.64.0.0/13
			headers:    map[string]string{"X-Forwarded-For": "198.51.100.9, 10.0.0.2"},
			want:       "198.51.100.9",
		},
		{
			name:       "untrusted public peer ignores spoofed forwarded headers",
			remoteAddr: "8.8.8.8:1234", // not Cloudflare, not private
			headers: map[string]string{
				"CF-Connecting-IP": "203.0.113.7",
				"X-Forwarded-For":  "203.0.113.7",
			},
			want: "8.8.8.8",
		},
		{
			name:       "loopback peer is trusted (tests / local proxy)",
			remoteAddr: "127.0.0.1:55555",
			headers:    map[string]string{"X-Forwarded-For": "198.51.100.9"},
			want:       "198.51.100.9",
		},
		{
			name:       "private peer is trusted (self-host behind private LB)",
			remoteAddr: "10.1.2.3:9000",
			headers:    map[string]string{"X-Real-IP": "198.51.100.42"},
			want:       "198.51.100.42",
		},
		{
			name:       "trusted peer with no forwarded headers uses peer IP",
			remoteAddr: "127.0.0.1:40000",
			headers:    map[string]string{},
			want:       "127.0.0.1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			for k, v := range tc.headers {
				h.Set(k, v)
			}
			if got := clientIP(tc.remoteAddr, h); got != tc.want {
				t.Errorf("clientIP(%q, %v) = %q, want %q", tc.remoteAddr, tc.headers, got, tc.want)
			}
		})
	}
}
