package relay

import "errors"

// Domain sentinel errors. These replace stringly-typed control flow
// (err.Error() == "device_revoked", strings.Contains(err, "between 1 and 365"),
// …) with errors.Is checks, so the transport adapters (REST + Connect-RPC) can
// map a single error value to a status code in one place instead of re-parsing
// message text. The Error() strings are kept identical to the previous inline
// fmt.Errorf messages so any response body that surfaced them stays
// byte-compatible.
var (
	// ErrDeviceRevoked is returned by GetAuthContext when the device token
	// belongs to a revoked device.
	ErrDeviceRevoked = errors.New("device_revoked")

	// ErrDemoExpired is returned by GetAuthContext when a demo session's TTL
	// has elapsed.
	ErrDemoExpired = errors.New("demo_expired")

	// ErrClipNotFound is returned by clip mutations when the (user, clip) pair
	// matches no row.
	ErrClipNotFound = errors.New("clip not found")

	// ErrDeviceLimitExceeded is returned by CompleteDeviceCode when approving
	// the device would exceed the user's plan device limit. Wrapping callers
	// append "user has N/M active devices" so the rendered message is unchanged.
	ErrDeviceLimitExceeded = errors.New("device_limit_exceeded")

	// ErrRetentionOutOfRange is returned by UpdateDeviceRetention when the
	// requested retention is outside the allowed 1..365 day window.
	ErrRetentionOutOfRange = errors.New("retention days must be between 1 and 365")

	// ErrRateLimited is returned by the shared device-code-start path when the
	// requester IP exceeds the per-IP rate limit.
	ErrRateLimited = errors.New("rate limit exceeded")

	// errDeviceProvisionFailed marks the device-code completion failing at the
	// CreateDeviceForUser stage (a server/DB fault) rather than at the
	// CompleteDeviceCode stage (a bad/expired user_code). Transports map the
	// former to 500 / CodeInternal and the latter to 400 / CodeInvalidArgument.
	errDeviceProvisionFailed = errors.New("device provisioning failed")
)
