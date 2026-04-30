// Time conversion helpers for crossing the in-memory `time.Time` ↔ proto
// `string` boundary. The relay stores timestamps as native `time.Time` in
// SQLite; proto messages serialize timestamps as RFC 3339 strings (matching
// what the legacy hand-written types already emit on the wire).

package protocol

import "time"

// FormatRFC3339 renders a UTC timestamp as RFC 3339 — what the proto wire
// format expects.
func FormatRFC3339(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

// FormatRFC3339Ptr renders a nullable timestamp into the `*string` shape
// proto-generated `optional` fields use. nil in → nil out.
func FormatRFC3339Ptr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := FormatRFC3339(*t)
	return &s
}

// ParseRFC3339 parses an RFC 3339 string back into a `time.Time`.
// Convenience for the few places we need to compare proto-string
// timestamps against `time.Now()` server-side.
func ParseRFC3339(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, s)
}
