package relay

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"

	cinchv1 "github.com/cinchcli/relay/internal/cinchv1"
	"github.com/cinchcli/relay/internal/cinchv1/cinchv1connect"
)

// extractRequesterIP returns the client IP from request headers, preferring
// X-Forwarded-For (first hop), falling back to X-Real-IP, then empty. Used
// for audit logging on device_codes rows; the reverse proxy is responsible
// for setting these headers.
func extractRequesterIP(h http.Header) string {
	if xff := h.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	return h.Get("X-Real-IP")
}

// connectAuthServer implements cinchv1connect.AuthServiceHandler.
// Mirrors AuthLogin handler logic — same store calls, same token generation.
type connectAuthServer struct {
	h *Handler
}

var _ cinchv1connect.AuthServiceHandler = (*connectAuthServer)(nil)

// requireConnectAuthHeaders resolves a Bearer token and sets X-User-ID / X-Device-ID
// on the provided http.Header. Works for both unary (req.Header()) and streaming
// (conn.RequestHeader()) contexts.
func (h *Handler) requireConnectAuthHeaders(headers http.Header) error {
	// Defense in depth: never trust inbound identity headers; they are set
	// below only after the bearer token is verified.
	stripClientIdentityHeaders(headers)

	token := strings.TrimPrefix(headers.Get("Authorization"), "Bearer ")
	if token == "" {
		return connect.NewError(connect.CodeUnauthenticated, errMsg("no auth token provided"))
	}

	ctx, err := h.store.GetAuthContext(token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return connect.NewError(connect.CodeUnauthenticated, errMsg("invalid or expired token"))
		}
		if errors.Is(err, ErrDeviceRevoked) {
			return connect.NewError(connect.CodePermissionDenied, errMsg("device revoked"))
		}
		if errors.Is(err, ErrDemoExpired) {
			return connect.NewError(connect.CodeUnauthenticated, errMsg("demo session expired"))
		}
		slog.Error("GetAuthContext error", "err", err)
		return connect.NewError(connect.CodeUnauthenticated, errMsg("invalid token"))
	}

	headers.Set("X-Device-ID", ctx.DeviceID)
	headers.Set("X-User-ID", ctx.UserID)
	if ctx.IsAdmin {
		headers.Set("X-Is-Admin", "true")
	}
	if ctx.IsDemo {
		headers.Set("X-Is-Demo", "true")
	}
	return nil
}

// requireConnectAuth is a convenience wrapper for unary-call request objects.
func (h *Handler) requireConnectAuth(req connect.AnyRequest) error {
	return h.requireConnectAuthHeaders(req.Header())
}

// authConnectInterceptor applies RequireAuth only for procedures that need it.
func (h *Handler) authConnectInterceptor() connect.UnaryInterceptorFunc {
	authedProcedures := map[string]bool{
		cinchv1connect.AuthServiceDeviceCodeCompleteProcedure:      true,
		cinchv1connect.AuthServiceDeviceCodeDenyProcedure:          true,
		cinchv1connect.AuthServiceRevokeDeviceProcedure:            true,
		cinchv1connect.AuthServiceKeyBundlePutProcedure:            true,
		cinchv1connect.AuthServiceKeyBundleGetProcedure:            true,
		cinchv1connect.AuthServiceKeyBundleRetryProcedure:          true,
		cinchv1connect.AuthServiceRegisterDevicePublicKeyProcedure: true,
		cinchv1connect.AuthServiceSetDisplayNameProcedure:          true,
	}
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if !authedProcedures[req.Spec().Procedure] {
				return next(ctx, req)
			}
			if err := h.requireConnectAuth(req); err != nil {
				return nil, err
			}
			return next(ctx, req)
		}
	}
}

func errMsg(msg string) error {
	return &connectErrMsg{msg}
}

type connectErrMsg struct{ s string }

func (e *connectErrMsg) Error() string { return e.s }

// ─── Login ──────────────────────────────────────────────────

// Login mirrors the REST AuthLogin handler — invite-gated anonymous account +
// first device row. PairToken is reserved in the proto and intentionally left unset.
func (s *connectAuthServer) Login(ctx context.Context, req *connect.Request[cinchv1.LoginRequest]) (*connect.Response[cinchv1.LoginResponse], error) {
	// OAuth gate: refuse direct account creation when OAuth is configured,
	// matching the REST AuthLogin behavior (security finding 3).
	if s.h.OAuth != nil && (s.h.OAuth.GitHub != nil || s.h.OAuth.Google != nil) {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("oauth_required"))
	}

	// IP rate limiter: mirror the per-IP window applied by REST AuthLogin.
	ip := req.Header().Get("X-Forwarded-For")
	if ip == "" {
		if addr := req.Peer().Addr; addr != "" {
			ip, _, _ = strings.Cut(addr, ":")
		}
	} else {
		ip = strings.TrimSpace(strings.SplitN(ip, ",", 2)[0])
	}
	if s.h.checkLoginRateLimit(ip) {
		return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("rate_limited"))
	}

	// Invite gate: required when OAuth is off (same rule as REST AuthLogin).
	if req.Msg.InviteCode == nil || *req.Msg.InviteCode == "" {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("invite_required"))
	}
	hash := HashInviteCode(*req.Msg.InviteCode)
	if err := s.h.store.RedeemInvite(hash); err != nil {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("invite_invalid"))
	}

	hostname := "unknown"
	if req.Msg.Hostname != nil && *req.Msg.Hostname != "" {
		hostname = *req.Msg.Hostname
	}

	userID := ulid.Make().String()
	if err := s.h.store.CreateUser(userID); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if req.Msg.DisplayName != nil && *req.Msg.DisplayName != "" {
		if err := s.h.store.SetUserDisplayName(userID, *req.Msg.DisplayName); err != nil {
			slog.Error("set display name failed", "user", userID, "err", err)
		}
	}

	// First user on the relay becomes admin automatically.
	if n, err := s.h.store.CountUsers(); err == nil && n == 1 {
		if err := s.h.store.SetUserAdmin(userID, true); err != nil {
			slog.Error("promote first user to admin failed", "user", userID, "err", err)
		}
	}

	deviceID := ulid.Make().String()
	deviceToken := generateToken()
	if err := s.h.store.RegisterDeviceWithToken(userID, deviceID, hostname, deviceToken); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&cinchv1.LoginResponse{
		Token:    deviceToken,
		UserId:   userID,
		DeviceId: deviceID,
	}), nil
}

// ─── DeviceCodeStart ─────────────────────────────────────────

func (s *connectAuthServer) DeviceCodeStart(ctx context.Context, req *connect.Request[cinchv1.DeviceCodeStartRequest]) (*connect.Response[cinchv1.DeviceCodeStartResponse], error) {
	hostname := "unknown"
	if req.Msg.Hostname != nil && *req.Msg.Hostname != "" {
		hostname = *req.Msg.Hostname
	}
	machineID := ""
	if req.Msg.MachineId != nil {
		machineID = *req.Msg.MachineId
	}
	userHint := ""
	if req.Msg.UserHint != nil {
		userHint = *req.Msg.UserHint
	}
	resp, err := s.h.startDeviceCode(hostname, machineID, userHint, extractRequesterIP(req.Header()))
	if err != nil {
		if errors.Is(err, ErrRateLimited) {
			return nil, connect.NewError(connect.CodeResourceExhausted, errMsg("rate limit exceeded"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	baseURL := s.h.BaseURL
	verificationURI := baseURL + "/auth/browser?device_code=" + resp.UserCode

	return connect.NewResponse(&cinchv1.DeviceCodeStartResponse{
		DeviceCode:      resp.DeviceCode,
		UserCode:        resp.UserCode,
		VerificationUri: verificationURI,
		ExpiresIn:       resp.ExpiresIn,
		Interval:        resp.Interval,
		IntervalMs:      resp.IntervalMs,
	}), nil
}

// ─── DeviceCodePoll ──────────────────────────────────────────

func (s *connectAuthServer) DeviceCodePoll(ctx context.Context, req *connect.Request[cinchv1.DeviceCodePollRequest]) (*connect.Response[cinchv1.DeviceCodePollResponse], error) {
	if req.Msg.Code == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errMsg("code is required"))
	}

	resp, err := s.h.store.PollDeviceCode(req.Msg.Code)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}

	switch resp.Status {
	case "expired":
		return nil, connect.NewError(connect.CodeFailedPrecondition, errMsg("device code expired"))
	case "complete":
		// Store now returns the proto type natively, so we can pass through.
		return connect.NewResponse(resp), nil
	case "denied":
		return connect.NewResponse(&cinchv1.DeviceCodePollResponse{Status: "denied"}), nil
	default:
		return connect.NewResponse(&cinchv1.DeviceCodePollResponse{Status: "pending"}), nil
	}
}

// ─── DeviceCodeComplete ──────────────────────────────────────

func (s *connectAuthServer) DeviceCodeComplete(ctx context.Context, req *connect.Request[cinchv1.DeviceCodeCompleteRequest]) (*connect.Response[cinchv1.DeviceCodeCompleteResponse], error) {
	// Identity comes from the verified bearer token (set by the auth
	// interceptor), NOT from req.Msg.UserId/DeviceId/Token — those client-
	// supplied fields are ignored. The new device's credentials are minted
	// server-side, matching the HTTP twin. This closes the divergence where the
	// Connect path trusted the caller to name the account and device it was
	// completing for.
	approverUserID := req.Header().Get("X-User-ID")
	if approverUserID == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated, errMsg("auth required"))
	}
	if req.Msg.UserCode == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errMsg("user_code is required"))
	}

	if err := s.h.completeDeviceCodeForCaller(approverUserID, req.Msg.UserCode); err != nil {
		switch {
		case errors.Is(err, errDeviceProvisionFailed):
			return nil, connect.NewError(connect.CodeInternal, err)
		case errors.Is(err, ErrDeviceLimitExceeded):
			return nil, connect.NewError(connect.CodeResourceExhausted, err)
		default:
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
	}

	return connect.NewResponse(&cinchv1.DeviceCodeCompleteResponse{
		Status: "complete",
	}), nil
}

// ─── DeviceCodeDeny ──────────────────────────────────────────

// DeviceCodeDeny rejects a pending device-code from an already-signed-in
// device. The remote CLI's next DeviceCodePoll returns status="denied".
// Requires auth: the caller's X-User-ID must match the pending row's
// pending_user_id, so only the targeted user (set by user_hint matching at
// CreateDeviceCode time) can deny their own pending login requests.
func (s *connectAuthServer) DeviceCodeDeny(ctx context.Context, req *connect.Request[cinchv1.DeviceCodeDenyRequest]) (*connect.Response[cinchv1.DeviceCodeDenyResponse], error) {
	callerUserID := req.Header().Get("X-User-ID")
	if callerUserID == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated, errMsg("auth required"))
	}
	if req.Msg.UserCode == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errMsg("user_code is required"))
	}
	if err := s.h.store.DenyDeviceCode(req.Msg.UserCode, callerUserID); err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}
	return connect.NewResponse(&cinchv1.DeviceCodeDenyResponse{Ok: true}), nil
}

// ─── RevokeDevice ────────────────────────────────────────────

func (s *connectAuthServer) RevokeDevice(ctx context.Context, req *connect.Request[cinchv1.RevokeDeviceRequest]) (*connect.Response[cinchv1.RevokeDeviceResponse], error) {
	callerUserID := req.Header().Get("X-User-ID")
	if req.Msg.DeviceId == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errMsg("device_id is required"))
	}

	ownerID, err := s.h.store.DeviceOwner(req.Msg.DeviceId)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		// Fail closed on a DB fault, matching the HTTP twin: never fold a
		// transient error into "not found", which could mask a real failure
		// or let a cross-user revoke slip through under a different ordering.
		return nil, connect.NewError(connect.CodeInternal, errMsg("revoke failed"))
	}
	if errors.Is(err, sql.ErrNoRows) || ownerID != callerUserID {
		// Treat unknown and cross-user devices alike — no existence oracle.
		return nil, connect.NewError(connect.CodeNotFound, errMsg("device not found"))
	}

	revokedAt, err := s.h.store.RevokeDevice(req.Msg.DeviceId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	s.h.hub.SendToDevice(ownerID, req.Msg.DeviceId, &cinchv1.ServerEvent{
		Event: &cinchv1.ServerEvent_Revoked{
			Revoked: &cinchv1.RevokedEvent{Reason: "revoked_by_user"},
		},
	})

	return connect.NewResponse(&cinchv1.RevokeDeviceResponse{
		Ok:        true,
		DeviceId:  req.Msg.DeviceId,
		RevokedAt: revokedAt.Format(time.RFC3339),
	}), nil
}

// ─── KeyBundleRetry ──────────────────────────────────────────

// KeyBundleRetry re-broadcasts key_exchange_requested for the calling
// device. Used by `cinch auth retry-key` when the initial key handoff
// missed (no key-bearer was online). Returns FailedPrecondition when the
// device has not yet registered a public key (nothing to broadcast about).
func (s *connectAuthServer) KeyBundleRetry(
	ctx context.Context,
	req *connect.Request[cinchv1.KeyBundleRetryRequest],
) (*connect.Response[cinchv1.KeyBundleRetryResponse], error) {
	userID := req.Header().Get("X-User-ID")
	deviceID := req.Header().Get("X-Device-ID")
	if userID == "" || deviceID == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated, errMsg("missing user or device"))
	}

	hostname, pubKey, err := s.h.store.GetDeviceHostnameAndPubKey(deviceID)
	if err == sql.ErrNoRows {
		return nil, connect.NewError(connect.CodeNotFound, errMsg("device not found"))
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if pubKey == "" {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errMsg("device has not registered a public key yet"))
	}

	s.h.hub.SendToUser(userID, &cinchv1.ServerEvent{
		Event: &cinchv1.ServerEvent_KeyExchange{
			KeyExchange: &cinchv1.KeyExchangeEvent{
				DeviceId: deviceID,
				Hostname: hostname,
			},
		},
	})

	return connect.NewResponse(&cinchv1.KeyBundleRetryResponse{Ok: true}), nil
}

// ─── KeyBundlePut ────────────────────────────────────────────

func (s *connectAuthServer) KeyBundlePut(ctx context.Context, req *connect.Request[cinchv1.KeyBundlePutRequest]) (*connect.Response[cinchv1.KeyBundlePutResponse], error) {
	callerUserID := req.Header().Get("X-User-ID")
	if req.Msg.DeviceId == "" || req.Msg.EphemeralPublicKey == "" || req.Msg.EncryptedBundle == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errMsg("device_id, ephemeral_public_key, encrypted_bundle are required"))
	}

	targetOwner, err := s.h.store.DeviceOwner(req.Msg.DeviceId)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errMsg("device not found"))
	}
	if callerUserID != targetOwner {
		return nil, connect.NewError(connect.CodePermissionDenied, errMsg("cannot set key bundle for another user's device"))
	}

	if err := s.h.store.SaveKeyBundle(req.Msg.DeviceId, req.Msg.EphemeralPublicKey, req.Msg.EncryptedBundle); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&cinchv1.KeyBundlePutResponse{Ok: true}), nil
}

// ─── KeyBundleGet ────────────────────────────────────────────

func (s *connectAuthServer) KeyBundleGet(ctx context.Context, req *connect.Request[cinchv1.KeyBundleGetRequest]) (*connect.Response[cinchv1.KeyBundleGetResponse], error) {
	deviceID := req.Header().Get("X-Device-ID")
	if deviceID == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated, errMsg("per-device token required"))
	}

	eph, bundle, err := s.h.store.GetKeyBundle(deviceID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	pendingSince := ""
	if eph == "" || bundle == "" {
		ts, _ := s.h.store.GetKeyBundlePendingSince(deviceID)
		if !ts.IsZero() {
			pendingSince = ts.UTC().Format(time.RFC3339)
		}
	}

	return connect.NewResponse(&cinchv1.KeyBundleGetResponse{
		EphemeralPublicKey: eph,
		EncryptedBundle:    bundle,
		PendingSince:       pendingSince,
	}), nil
}

// ─── RegisterDevicePublicKey ────────────────────────────────

// RegisterDevicePublicKey stores the X25519 public key for the calling
// device so the relay can include it in ListPendingKeyExchanges sweeps
// and broadcast key_exchange_requested for it. Bearer-authenticated;
// the device_id is taken from the X-Device-ID header set by the auth
// interceptor.
func (s *connectAuthServer) RegisterDevicePublicKey(
	ctx context.Context,
	req *connect.Request[cinchv1.RegisterDevicePublicKeyRequest],
) (*connect.Response[cinchv1.RegisterDevicePublicKeyResponse], error) {
	deviceID := req.Header().Get("X-Device-ID")
	userID := req.Header().Get("X-User-ID")
	if deviceID == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated, errMsg("missing device"))
	}
	if req.Msg.PublicKey == "" || req.Msg.Fingerprint == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errMsg("public_key and fingerprint are required"))
	}
	if err := s.h.store.SetDevicePublicKey(deviceID, req.Msg.PublicKey, req.Msg.Fingerprint); err != nil {
		if err == sql.ErrNoRows {
			return nil, connect.NewError(connect.CodeNotFound, errMsg("device not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	// Best-effort broadcast: matches the legacy HTTP handler — a bearer
	// responds immediately instead of letting the device block on its
	// 30s key-bundle poll waiting for the next sweep.
	if userID != "" {
		if hostname, _, hostErr := s.h.store.GetDeviceHostnameAndPubKey(deviceID); hostErr == nil {
			s.h.hub.SendToUser(userID, &cinchv1.ServerEvent{
				Event: &cinchv1.ServerEvent_KeyExchange{
					KeyExchange: &cinchv1.KeyExchangeEvent{
						DeviceId: deviceID,
						Hostname: hostname,
					},
				},
			})
		}
	}
	return connect.NewResponse(&cinchv1.RegisterDevicePublicKeyResponse{Ok: true}), nil
}

// ─── SetDisplayName ──────────────────────────────────────

// SetDisplayName updates users.display_name for the calling user.
// Trims whitespace; rejects empty input and inputs over 64 bytes.
// Mirrors POST /auth/display-name (Task 8).
func (s *connectAuthServer) SetDisplayName(
	ctx context.Context,
	req *connect.Request[cinchv1.SetDisplayNameRequest],
) (*connect.Response[cinchv1.SetDisplayNameResponse], error) {
	userID := req.Header().Get("X-User-ID")
	if userID == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated, errMsg("auth required"))
	}
	trimmed := strings.TrimSpace(req.Msg.DisplayName)
	if trimmed == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errMsg("display_name must not be empty"))
	}
	if len(trimmed) > 64 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errMsg("display_name max 64 bytes"))
	}
	if err := s.h.store.SetUserDisplayName(userID, trimmed); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&cinchv1.SetDisplayNameResponse{
		Ok:          true,
		DisplayName: trimmed,
	}), nil
}

// newAuthConnectHandler wraps the Connect AuthService handler with auth interceptor.
func (h *Handler) newAuthConnectHandler() (string, http.Handler) {
	return cinchv1connect.NewAuthServiceHandler(
		&connectAuthServer{h: h},
		connect.WithInterceptors(h.authConnectInterceptor()),
	)
}
