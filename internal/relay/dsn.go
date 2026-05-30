package relay

import (
	"net/url"
	"strings"
)

// normalizePostgresDSN makes postgres:// and postgresql:// URLs safe to parse when
// the password contains reserved characters (e.g. '/', '?', '#').
//
// Operators should ideally percent-encode the password themselves, but in
// practice DATABASE_URL often comes from dashboards/secret stores as a raw URL.
// We only rewrite URL-form DSNs and only touch the password (userinfo) portion.
// Non-URL DSNs ("key=value" style) are returned unchanged.
func normalizePostgresDSN(dsn string) string {
	if dsn == "" {
		return dsn
	}

	// Only attempt to normalize URL-form DSNs.
	if !strings.Contains(dsn, "://") {
		return dsn
	}

	u, err := url.Parse(dsn)
	if err == nil {
		if u.Scheme != "postgres" && u.Scheme != "postgresql" {
			return dsn
		}
		// url.URL.String() re-escapes userinfo correctly, without double-encoding
		// already-escaped passwords.
		return u.String()
	}

	// Salvage common "raw password" cases where reserved characters break parsing.
	// We treat the last '@' after the scheme as the userinfo/host separator.
	i := strings.Index(dsn, "://")
	if i <= 0 {
		return dsn
	}
	scheme := dsn[:i]
	if scheme != "postgres" && scheme != "postgresql" {
		return dsn
	}

	after := dsn[i+3:]
	at := strings.LastIndex(after, "@")
	if at == -1 {
		return dsn
	}
	userinfoRaw := after[:at]
	hostAndRest := after[at+1:]

	colon := strings.Index(userinfoRaw, ":")
	if colon == -1 {
		return dsn
	}
	username := userinfoRaw[:colon]
	password := userinfoRaw[colon+1:]

	// Split host from the rest (/path?query#frag).
	split := strings.IndexAny(hostAndRest, "/?#")
	host := hostAndRest
	rest := ""
	if split != -1 {
		host = hostAndRest[:split]
		rest = hostAndRest[split:]
	}

	base, err2 := url.Parse(scheme + "://" + host + rest)
	if err2 != nil {
		return dsn
	}
	base.User = url.UserPassword(username, password)
	return base.String()
}
