package relay

import (
	"context"
	"log"
	"net/http"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cinchcli/protocol"
	cinchv1 "github.com/cinchcli/relay/internal/gen/cinch/v1"
	"github.com/cinchcli/relay/internal/gen/cinch/v1/cinchv1connect"
)

type connectClipsServer struct {
	h *Handler
}

var _ cinchv1connect.ClipsServiceHandler = (*connectClipsServer)(nil)

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

func protoClip(c *protocol.Clip) *cinchv1.Clip {
	pc := &cinchv1.Clip{
		ClipId:      c.ID,
		UserId:      c.UserID,
		Content:     c.Content,
		ContentType: protoContentType(c.ContentType),
		Source:      c.Source,
		Label:       c.Label,
		ByteSize:    int32(c.ByteSize),
		CreatedAt:   timestamppb.New(c.CreatedAt),
		Encrypted:   c.Encrypted,
	}
	if c.MediaPath != "" {
		pc.MediaPath = &c.MediaPath
	}
	if c.TTL != 0 {
		ttl := c.TTL
		pc.Ttl = &ttl
	}
	return pc
}

func protoContentType(ct protocol.ContentType) cinchv1.ContentType {
	switch ct {
	case protocol.ContentText:
		return cinchv1.ContentType_CONTENT_TYPE_TEXT
	case protocol.ContentURL:
		return cinchv1.ContentType_CONTENT_TYPE_URL
	case protocol.ContentCode:
		return cinchv1.ContentType_CONTENT_TYPE_CODE
	case protocol.ContentImage:
		return cinchv1.ContentType_CONTENT_TYPE_IMAGE
	default:
		return cinchv1.ContentType_CONTENT_TYPE_UNSPECIFIED
	}
}

func protocolContentType(ct cinchv1.ContentType) protocol.ContentType {
	switch ct {
	case cinchv1.ContentType_CONTENT_TYPE_TEXT:
		return protocol.ContentText
	case cinchv1.ContentType_CONTENT_TYPE_URL:
		return protocol.ContentURL
	case cinchv1.ContentType_CONTENT_TYPE_CODE:
		return protocol.ContentCode
	case cinchv1.ContentType_CONTENT_TYPE_IMAGE:
		return protocol.ContentImage
	default:
		return protocol.ContentText
	}
}

// ─── PushClip ────────────────────────────────────────────────

func (s *connectClipsServer) PushClip(ctx context.Context, req *connect.Request[cinchv1.PushClipRequest]) (*connect.Response[cinchv1.PushClipResponse], error) {
	userID := req.Header().Get("X-User-ID")
	if req.Msg.Content == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errMsg("content is required"))
	}

	pushReq := &protocol.PushRequest{
		Content:     req.Msg.Content,
		ContentType: protocolContentType(req.Msg.ContentType),
		Label:       req.Msg.Label,
		Source:      req.Msg.Source,
		ByteSize:    int(req.Msg.ByteSize),
		Encrypted:   req.Msg.Encrypted,
	}
	if req.Msg.TargetDeviceId != nil {
		pushReq.TargetDeviceID = *req.Msg.TargetDeviceId
	}
	if req.Msg.Ttl != nil {
		pushReq.TTL = int(*req.Msg.Ttl)
	}

	// Targeted push — check online before saving (D-10).
	if pushReq.TargetDeviceID != "" {
		if !s.h.hub.IsDeviceOnline(userID, pushReq.TargetDeviceID) {
			return nil, connect.NewError(connect.CodeUnavailable, errMsg("device is not currently online"))
		}
		clip, err := s.h.store.SaveClip(userID, pushReq)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		if pushReq.Source != "" {
			s.h.store.UpdateDeviceActivity(userID, pushReq.Source)
		}
		if err := s.h.hub.SendToDevice(userID, pushReq.TargetDeviceID, protocol.WSMessage{
			Action: protocol.ActionNewClip, Clip: clip,
		}); err != nil {
			log.Printf("connectClipsServer.PushClip: SendToDevice failed: %v", err)
		}
		return connect.NewResponse(&cinchv1.PushClipResponse{
			ClipId:   clip.ID,
			ByteSize: int32(clip.ByteSize),
		}), nil
	}

	// Demo restrictions.
	isDemo, _ := s.h.store.IsDemoUser(userID)
	if isDemo {
		if req.Msg.ContentType != cinchv1.ContentType_CONTENT_TYPE_UNSPECIFIED &&
			req.Msg.ContentType != cinchv1.ContentType_CONTENT_TYPE_TEXT {
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

	clip, err := s.h.store.SaveClip(userID, pushReq)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	if isDemo {
		if err := s.h.store.IncrementDemoCounter(); err != nil {
			log.Printf("connectClipsServer.PushClip: demo counter increment failed: %v", err)
		}
	}

	if pushReq.Source != "" {
		if err := s.h.store.UpdateDeviceActivity(userID, pushReq.Source); err != nil {
			log.Printf("connectClipsServer.PushClip: device activity update failed: %v", err)
		}
	}

	if err := s.h.hub.SendClip(userID, clip); err != nil {
		log.Printf("connectClipsServer.PushClip: ws broadcast failed for %s: %v", userID, err)
	}

	return connect.NewResponse(&cinchv1.PushClipResponse{
		ClipId:   clip.ID,
		ByteSize: int32(clip.ByteSize),
	}), nil
}

// ─── ListClips ───────────────────────────────────────────────

func (s *connectClipsServer) ListClips(ctx context.Context, req *connect.Request[cinchv1.ListClipsRequest]) (*connect.Response[cinchv1.ListClipsResponse], error) {
	userID := req.Header().Get("X-User-ID")
	clips, err := s.h.store.ListClips(userID, 50)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	pclips := make([]*cinchv1.Clip, 0, len(clips))
	for _, c := range clips {
		pclips = append(pclips, protoClip(c))
	}
	return connect.NewResponse(&cinchv1.ListClipsResponse{Clips: pclips}), nil
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
	return connect.NewResponse(&cinchv1.GetLatestClipResponse{Clip: protoClip(clip)}), nil
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
	return connect.NewResponse(&cinchv1.DeleteClipResponse{Ok: true}), nil
}

// newClipsConnectHandler wraps the Connect ClipsService handler with auth interceptor.
func (h *Handler) newClipsConnectHandler() (string, http.Handler) {
	return cinchv1connect.NewClipsServiceHandler(
		&connectClipsServer{h: h},
		connect.WithInterceptors(h.clipsConnectInterceptor()),
	)
}
