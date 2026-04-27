package relay

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"log"
	"net/http"
	"strings"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cinchcli/protocol"
	cinchv1 "github.com/cinchcli/relay/internal/gen/cinch/v1"
	"github.com/cinchcli/relay/internal/gen/cinch/v1/cinchv1connect"
)

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
	if derr == nil {
		if revoked {
			return connect.NewError(connect.CodePermissionDenied, errMsg("device revoked"))
		}
		userID, err := h.store.DeviceOwner(deviceID)
		if err != nil {
			return connect.NewError(connect.CodeUnauthenticated, errMsg("invalid token"))
		}
		headers.Set("X-Device-ID", deviceID)
		headers.Set("X-User-ID", userID)
		go h.store.CloseGraceEarlyIfNeeded(userID)
		return nil
	}

	userID, err := h.store.UserByToken(token)
	if err != nil {
		return connect.NewError(connect.CodeUnauthenticated, errMsg("invalid or expired token"))
	}
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
		cinchv1connect.AuthServiceDeviceCodeCompleteProcedure: true,
		cinchv1connect.AuthServiceRevokeDeviceProcedure:       true,
		cinchv1connect.AuthServiceRotatePairTokenProcedure:    true,
		cinchv1connect.AuthServiceKeyBundlePutProcedure:       true,
		cinchv1connect.AuthServiceKeyBundleGetProcedure:       true,
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

func (s *connectAuthServer) Login(ctx context.Context, req *connect.Request[cinchv1.LoginRequest]) (*connect.Response[cinchv1.LoginResponse], error) {
	hostname := "unknown"
	if req.Msg.Hostname != nil && *req.Msg.Hostname != "" {
		hostname = *req.Msg.Hostname
	}

	userID := ulid.Make().String()
	token := generateToken()
	pairToken := generatePairToken()

	if err := s.h.store.CreateUser(userID, token, pairToken); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	deviceID := ulid.Make().String()
	if err := s.h.store.RegisterDeviceWithToken(userID, deviceID, hostname, token); err != nil {
		log.Printf("connectAuthServer.Login: RegisterDeviceWithToken failed for %s: %v", userID[:8], err)
		deviceID = ""
	} else {
		_, _ = s.h.store.db.Exec(
			`UPDATE users SET token_migrated_at = COALESCE(token_migrated_at, CURRENT_TIMESTAMP) WHERE id = ?`,
			userID,
		)
	}

	return connect.NewResponse(&cinchv1.LoginResponse{
		Token:     token,
		PairToken: pairToken,
		UserId:    userID,
		DeviceId:  deviceID,
	}), nil
}

// ─── Pair ───────────────────────────────────────────────────

func (s *connectAuthServer) Pair(ctx context.Context, req *connect.Request[cinchv1.PairRequest]) (*connect.Response[cinchv1.PairResponse], error) {
	if req.Msg.PairToken == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errMsg("pair_token is required"))
	}

	hostname := "unknown"
	if req.Msg.Hostname != nil && *req.Msg.Hostname != "" {
		hostname = *req.Msg.Hostname
	}

	userID, deviceID, deviceToken, err := s.h.store.ConsumePairTokenMintDevice(req.Msg.PairToken, hostname)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
	}

	if req.Msg.DevicePublicKey != nil && *req.Msg.DevicePublicKey != "" {
		pubKey := *req.Msg.DevicePublicKey
		fingerprint := ""
		if req.Msg.DeviceKeyFingerprint != nil {
			fingerprint = *req.Msg.DeviceKeyFingerprint
		}
		if fingerprint == "" {
			if rawPub, err := base64.RawURLEncoding.DecodeString(pubKey); err == nil {
				digest := sha256.Sum256(rawPub)
				fingerprint = hex.EncodeToString(digest[:8])
			}
		}
		if err := s.h.store.SetDevicePublicKey(deviceID, pubKey, fingerprint); err != nil {
			log.Printf("connectAuthServer.Pair: SetDevicePublicKey failed: %v", err)
		}
		s.h.hub.SendToUser(userID, protocol.WSMessage{
			Action:               protocol.ActionKeyExchangeRequested,
			DeviceID:             deviceID,
			Hostname:             hostname,
			DeviceKeyFingerprint: fingerprint,
		})
	}

	return connect.NewResponse(&cinchv1.PairResponse{
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

	resp, err := s.h.store.CreateDeviceCode(hostname)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	baseURL := s.h.BaseURL
	verificationURI := baseURL + "/auth/browser?device_code=" + resp.UserCode

	return connect.NewResponse(&cinchv1.DeviceCodeStartResponse{
		DeviceCode:      resp.DeviceCode,
		UserCode:        resp.UserCode,
		VerificationUri: verificationURI,
		ExpiresIn:       int32(resp.ExpiresIn),
		Interval:        int32(resp.Interval),
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
		return connect.NewResponse(&cinchv1.DeviceCodePollResponse{
			Status:   cinchv1.DeviceCodeStatus_DEVICE_CODE_STATUS_COMPLETE,
			Token:    &resp.Token,
			UserId:   &resp.UserID,
			DeviceId: &resp.DeviceID,
		}), nil
	}

	return connect.NewResponse(&cinchv1.DeviceCodePollResponse{
		Status: cinchv1.DeviceCodeStatus_DEVICE_CODE_STATUS_PENDING,
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

	s.h.hub.SendToDevice(ownerID, req.Msg.DeviceId, protocol.WSMessage{
		Action: protocol.ActionRevoked,
		Reason: "revoked_by_user",
	})

	return connect.NewResponse(&cinchv1.RevokeDeviceResponse{
		Ok:        true,
		DeviceId:  req.Msg.DeviceId,
		RevokedAt: timestamppb.New(revokedAt),
	}), nil
}

// ─── RotatePairToken ─────────────────────────────────────────

func (s *connectAuthServer) RotatePairToken(ctx context.Context, req *connect.Request[cinchv1.RotatePairTokenRequest]) (*connect.Response[cinchv1.RotatePairTokenResponse], error) {
	userID := req.Header().Get("X-User-ID")
	newPairToken := generatePairToken()
	_, err := s.h.store.db.Exec(
		"UPDATE users SET pair_token = ? WHERE id = ?", newPairToken, userID,
	)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&cinchv1.RotatePairTokenResponse{
		PairToken: newPairToken,
	}), nil
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
	if eph == "" || bundle == "" {
		return nil, connect.NewError(connect.CodeNotFound, errMsg("key bundle not yet available"))
	}

	return connect.NewResponse(&cinchv1.KeyBundleGetResponse{
		EphemeralPublicKey: eph,
		EncryptedBundle:    bundle,
	}), nil
}

// newAuthConnectHandler wraps the Connect AuthService handler with auth interceptor.
func (h *Handler) newAuthConnectHandler() (string, http.Handler) {
	return cinchv1connect.NewAuthServiceHandler(
		&connectAuthServer{h: h},
		connect.WithInterceptors(h.authConnectInterceptor()),
	)
}
