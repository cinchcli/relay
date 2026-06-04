package relay

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// cloudflareCIDRs is Cloudflare's published edge IP ranges (https://www.cloudflare.com/ips/).
// Forwarded client-IP headers are only trusted when the immediate peer falls in
// one of these (or is loopback/private). These ranges change occasionally —
// refresh from the published list when Cloudflare updates them.
var cloudflareCIDRs = mustParsePrefixes([]string{
	// IPv4 (https://www.cloudflare.com/ips-v4)
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
	// IPv6 (https://www.cloudflare.com/ips-v6)
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
})

func mustParsePrefixes(raw []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(raw))
	for _, s := range raw {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func isCloudflareIP(ip netip.Addr) bool {
	for _, p := range cloudflareCIDRs {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// isTrustedProxy reports whether forwarded client-IP headers from this peer may
// be believed: a Cloudflare edge (the hosted deployment), or a loopback/private
// address (tests and self-host behind a private load balancer).
func isTrustedProxy(ip netip.Addr) bool {
	return ip.IsLoopback() || ip.IsPrivate() || isCloudflareIP(ip)
}

// peerAddr parses the IP from a "host:port" remote address (http.Request.RemoteAddr
// or connect Request.Peer().Addr). Returns the zero Addr if it cannot be parsed.
func peerAddr(remoteAddr string) netip.Addr {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return addr
}

// clientIP returns the IP to use as a rate-limit identity. Forwarded headers
// (CF-Connecting-IP, then the first X-Forwarded-For hop, then X-Real-IP) are
// honored ONLY when the immediate peer is a trusted proxy; otherwise the peer
// IP is used, so a directly-connected client cannot forge its identity by
// setting these headers. Falls back to the raw remoteAddr when unparseable.
func clientIP(remoteAddr string, h http.Header) string {
	ip := peerAddr(remoteAddr)
	if ip.IsValid() && isTrustedProxy(ip) {
		if cf := strings.TrimSpace(h.Get("CF-Connecting-IP")); cf != "" {
			return cf
		}
		if xff := h.Get("X-Forwarded-For"); xff != "" {
			first := xff
			if i := strings.IndexByte(xff, ','); i >= 0 {
				first = xff[:i]
			}
			if first = strings.TrimSpace(first); first != "" {
				return first
			}
		}
		if xr := strings.TrimSpace(h.Get("X-Real-IP")); xr != "" {
			return xr
		}
	}
	if ip.IsValid() {
		return ip.String()
	}
	return remoteAddr
}
