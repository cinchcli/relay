package relay

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"connectrpc.com/connect"

	cinchv1 "github.com/cinchcli/relay/internal/gen/cinch/v1"
	"github.com/cinchcli/relay/internal/gen/cinch/v1/cinchv1connect"
)

type connectClipsServer struct {
	h *Handler
}

var _ cinchv1connect.ClipsServiceHandler = (*connectClipsServer)(nil)

// clampLimit ensures a limit value is within the acceptable range (1–100).
// If n <= 0, returns the default limit of 50.
// If n > 100, returns 100.
// Otherwise returns n as-is.
func clampLimit(n int) int {
	if n <= 0 {
		return 50
	}
	if n > 100 {
		return 100
	}
	return n
}

// clipsConnectInterceptor requires auth for all ClipsService procedures.
func (h *Handler) clipsConnectInterceptor() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if err := h.requireConnectAuth(req); err != nil {
				return nil, err
			}
			return next(ctx, req)
		}
	}
}

// ─── PushClip ────────────────────────────────────────────────

func (s *connectClipsServer) PushClip(ctx context.Context, req *connect.Request[cinchv1.PushClipRequest]) (*connect.Response[cinchv1.PushClipResponse], error) {
	userID := req.Header().Get("X-User-ID")
	if req.Msg.Content == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errMsg("content is required"))
	}

	// E2EE is mandatory for non-demo users.
	isDemoUser, _ := s.h.store.IsDemoUser(userID)
	if !isDemoUser && !req.Msg.Encrypted {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("encryption_required: server requires end-to-end encrypted clips"))
	}

	targetDeviceID := ""
	if req.Msg.TargetDeviceId != nil {
		targetDeviceID = *req.Msg.TargetDeviceId
	}

	// Targeted push — check online before saving (D-10).
	if targetDeviceID != "" {
		if !s.h.hub.IsDeviceOnline(userID, targetDeviceID) {
			return nil, connect.NewError(connect.CodeUnavailable, errMsg("device is not currently online"))
		}
		clip, err := s.h.store.SaveClip(userID, req.Msg)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		if req.Msg.Source != "" {
			s.h.store.UpdateDeviceActivity(userID, req.Msg.Source)
		}
		if err := s.h.hub.SendToDevice(userID, targetDeviceID, &cinchv1.ServerEvent{
			Event: &cinchv1.ServerEvent_NewClip{
				NewClip: &cinchv1.NewClipEvent{Clip: clip},
			},
		}); err != nil {
			log.Printf("connectClipsServer.PushClip: SendToDevice failed: %v", err)
		}
		return connect.NewResponse(&cinchv1.PushClipResponse{
			ClipId:   clip.ClipId,
			ByteSize: clip.ByteSize,
		}), nil
	}

	// Demo restrictions. isDemoUser was resolved above for the E2EE gate; reuse it here.
	if isDemoUser {
		if req.Msg.ContentType != "" && req.Msg.ContentType != "text" {
			return nil, connect.NewError(connect.CodePermissionDenied, errMsg("demo sessions accept text only"))
		}
		if len(req.Msg.Content) > demoMaxBytes {
			return nil, connect.NewError(connect.CodeResourceExhausted, errMsg("demo clip too large"))
		}
		count, _ := s.h.store.DemoClipCount(userID)
		if count >= demoMaxClips {
			return nil, connect.NewError(connect.CodeResourceExhausted, errMsg("demo clip limit reached"))
		}
	}

	clip, err := s.h.store.SaveClip(userID, req.Msg)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	if isDemoUser {
		if err := s.h.store.IncrementDemoCounter(); err != nil {
			log.Printf("connectClipsServer.PushClip: demo counter increment failed: %v", err)
		}
	}

	if req.Msg.Source != "" {
		if err := s.h.store.UpdateDeviceActivity(userID, req.Msg.Source); err != nil {
			log.Printf("connectClipsServer.PushClip: device activity update failed: %v", err)
		}
	}

	if err := s.h.hub.SendClip(userID, clip); err != nil {
		log.Printf("connectClipsServer.PushClip: ws broadcast failed for %s: %v", userID, err)
	}

	return connect.NewResponse(&cinchv1.PushClipResponse{
		ClipId:   clip.ClipId,
		ByteSize: clip.ByteSize,
	}), nil
}

// ─── ListClips ───────────────────────────────────────────────

func (s *connectClipsServer) ListClips(ctx context.Context, req *connect.Request[cinchv1.ListClipsRequest]) (*connect.Response[cinchv1.ListClipsResponse], error) {
	userID := req.Header().Get("X-User-ID")

	var sinceTime time.Time
	if req.Msg.Since != "" {
		t, err := time.Parse(time.RFC3339, req.Msg.Since)
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, errMsg("invalid since parameter: must be RFC 3339"))
		}
		sinceTime = t
	}

	limit := clampLimit(int(req.Msg.Limit))

	clips, err := s.h.store.ListClipsSince(userID, sinceTime, limit)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&cinchv1.ListClipsResponse{Clips: clips}), nil
}

// ─── GetLatestClip ───────────────────────────────────────────

func (s *connectClipsServer) GetLatestClip(ctx context.Context, req *connect.Request[cinchv1.GetLatestClipRequest]) (*connect.Response[cinchv1.GetLatestClipResponse], error) {
	userID := req.Header().Get("X-User-ID")
	if req.Msg.Source == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errMsg("source is required"))
	}

	clip, err := s.h.store.GetLatestClipBySource(userID, req.Msg.Source)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}
	return connect.NewResponse(&cinchv1.GetLatestClipResponse{Clip: clip}), nil
}

// ─── DeleteClip ──────────────────────────────────────────────

func (s *connectClipsServer) DeleteClip(ctx context.Context, req *connect.Request[cinchv1.DeleteClipRequest]) (*connect.Response[cinchv1.DeleteClipResponse], error) {
	userID := req.Header().Get("X-User-ID")
	if req.Msg.ClipId == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errMsg("clip_id is required"))
	}

	if err := s.h.store.DeleteClip(userID, req.Msg.ClipId); err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}
	if err := s.h.store.InsertTombstone(userID, req.Msg.ClipId); err != nil {
		log.Printf("InsertTombstone %s: %v", req.Msg.ClipId, err)
	}
	s.h.hub.SendClipDeleted(userID, req.Msg.ClipId)
	return connect.NewResponse(&cinchv1.DeleteClipResponse{Ok: true}), nil
}

// newClipsConnectHandler wraps the Connect ClipsService handler with auth interceptor.
func (h *Handler) newClipsConnectHandler() (string, http.Handler) {
	return cinchv1connect.NewClipsServiceHandler(
		&connectClipsServer{h: h},
		connect.WithInterceptors(h.clipsConnectInterceptor()),
	)
}
