package relay

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"

	cinchv1 "github.com/cinchcli/relay/internal/gen/cinch/v1"
	"github.com/cinchcli/relay/internal/gen/cinch/v1/cinchv1connect"
	"github.com/cinchcli/relay/internal/protocol"
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
	token := strings.TrimPrefix(headers.Get("Authorization"), "Bearer ")
	if token == "" {
		return connect.NewError(connect.CodeUnauthenticated, errMsg("no auth token provided"))
	}

	deviceID, revoked, derr := h.store.DeviceIDByToken(token)
	if derr != nil {
		return connect.NewError(connect.CodeUnauthenticated, errMsg("invalid or expired token"))
	}
	if revoked {
		return connect.NewError(connect.CodePermissionDenied, errMsg("device revoked"))
	}
	userID, err := h.store.DeviceOwner(deviceID)
	if err != nil {
		return connect.NewError(connect.CodeUnauthenticated, errMsg("invalid token"))
	}
	headers.Set("X-Device-ID", deviceID)
	headers.Set("X-User-ID", userID)
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
		cinchv1connect.AuthServiceRevokeDeviceProcedure:            true,
		cinchv1connect.AuthServiceKeyBundlePutProcedure:            true,
		cinchv1connect.AuthServiceKeyBundleGetProcedure:            true,
		cinchv1connect.AuthServiceKeyBundleRetryProcedure:          true,
		cinchv1connect.AuthServiceRegisterDevicePublicKeyProcedure: true,
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

// Login mirrors the REST AuthLogin handler — anonymous account + first
// device row, no master token (the users.token column was dropped in
// the OAuth-only migration). PairToken is reserved in the proto and
// intentionally left unset.
func (s *connectAuthServer) Login(ctx context.Context, req *connect.Request[cinchv1.LoginRequest]) (*connect.Response[cinchv1.LoginResponse], error) {
	hostname := "unknown"
	if req.Msg.Hostname != nil && *req.Msg.Hostname != "" {
		hostname = *req.Msg.Hostname
	}

	userID := ulid.Make().String()
	if err := s.h.store.CreateUser(userID); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
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
	requesterIP := extractRequesterIP(req.Header())

	resp, pendingUserID, err := s.h.store.CreateDeviceCode(hostname, machineID, userHint, requesterIP)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	if pendingUserID != "" {
		s.h.hub.BroadcastWSToUser(pendingUserID, &protocol.WSMessage{
			Action:      protocol.ActionDeviceCodePending,
			UserCode:    resp.UserCode,
			Hostname:    hostname,
			RequestedAt: time.Now().Unix(),
			// SourceRegion left blank; GeoIP lookup is a future enhancement.
		})
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

	if resp.Status == "expired" {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errMsg("device code expired"))
	}

	if resp.Status == "complete" {
		// Store now returns the proto type natively, so we can pass through.
		return connect.NewResponse(resp), nil
	}

	return connect.NewResponse(&cinchv1.DeviceCodePollResponse{
		Status: "pending",
	}), nil
}

// ─── DeviceCodeComplete ──────────────────────────────────────

func (s *connectAuthServer) DeviceCodeComplete(ctx context.Context, req *connect.Request[cinchv1.DeviceCodeCompleteRequest]) (*connect.Response[cinchv1.DeviceCodeCompleteResponse], error) {
	if req.Msg.UserCode == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errMsg("user_code is required"))
	}

	if err := s.h.store.CompleteDeviceCode(req.Msg.UserCode, req.Msg.UserId, req.Msg.DeviceId, req.Msg.Token); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	return connect.NewResponse(&cinchv1.DeviceCodeCompleteResponse{
		Status: "complete",
	}), nil
}

// ─── DeviceCodeDeny ──────────────────────────────────────────

// DeviceCodeDeny rejects a pending device-code from an already-signed-in
// device. The remote CLI's next DeviceCodePoll returns status="denied".
// Real implementation arrives in Task 1.7; for now this stub satisfies the
// generated AuthServiceHandler interface so the relay continues to build.
func (s *connectAuthServer) DeviceCodeDeny(ctx context.Context, req *connect.Request[cinchv1.DeviceCodeDenyRequest]) (*connect.Response[cinchv1.DeviceCodeDenyResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errMsg("not implemented yet"))
}

// ─── RevokeDevice ────────────────────────────────────────────

func (s *connectAuthServer) RevokeDevice(ctx context.Context, req *connect.Request[cinchv1.RevokeDeviceRequest]) (*connect.Response[cinchv1.RevokeDeviceResponse], error) {
	callerUserID := req.Header().Get("X-User-ID")
	if req.Msg.DeviceId == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errMsg("device_id is required"))
	}

	ownerID, err := s.h.store.DeviceOwner(req.Msg.DeviceId)
	if err != nil || ownerID != callerUserID {
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
	return connect.NewResponse(&cinchv1.RegisterDevicePublicKeyResponse{Ok: true}), nil
}

// newAuthConnectHandler wraps the Connect AuthService handler with auth interceptor.
func (h *Handler) newAuthConnectHandler() (string, http.Handler) {
	return cinchv1connect.NewAuthServiceHandler(
		&connectAuthServer{h: h},
		connect.WithInterceptors(h.authConnectInterceptor()),
	)
}
