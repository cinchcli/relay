// Package internalauth authorizes the relay's machine-to-machine /internal/*
// endpoints (called by the biz billing control plane). It supports
// per-direction least-privilege secrets and comma-separated dual-accept
// rotation, so a write-only credential cannot read the user list and a secret
// can be rotated with zero downtime ("new,prev").
package internalauth

import (
	"crypto/subtle"
	"strings"
)

// Result is the outcome of an internal-secret authorization check.
type Result int

const (
	// Disabled means no secret is configured for the endpoint. Self-hosters
	// leave the secrets unset, so /internal/* is disabled by default.
	Disabled Result = iota
	// Denied means a secret is configured but the bearer token did not match.
	Denied
	// OK means the bearer token matched a configured secret.
	OK
)

// Check authorizes an Authorization header against one or more secret specs.
// Each spec may itself be a comma-separated list so several secrets are
// accepted at once (zero-downtime rotation: deploy "new,prev", then drop
// "prev"). Empty and whitespace-only candidates are ignored, so passing an
// unset env var is harmless. If no spec yields a usable secret the endpoint is
// Disabled; otherwise the bearer token is compared in constant time against
// every candidate. All candidates are scanned regardless of an early match so
// timing does not leak how many secrets are configured.
func Check(authHeader string, secretSpecs ...string) Result {
	token := strings.TrimPrefix(authHeader, "Bearer ")
	configured := false
	matched := false
	for _, spec := range secretSpecs {
		for _, candidate := range strings.Split(spec, ",") {
			candidate = strings.TrimSpace(candidate)
			if candidate == "" {
				continue
			}
			configured = true
			if subtle.ConstantTimeCompare([]byte(token), []byte(candidate)) == 1 {
				matched = true
			}
		}
	}
	switch {
	case !configured:
		return Disabled
	case !matched:
		return Denied
	default:
		return OK
	}
}
