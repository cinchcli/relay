package relay

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"

	cinchv1 "github.com/cinchcli/relay/internal/cinchv1"
	"github.com/cinchcli/relay/internal/cinchv1/cinchv1connect"
	"github.com/cinchcli/relay/internal/media"
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

// uploadImageMedia offloads the encrypted bytes of an image clip into the
// configured media store (S3 or local FS) at a fresh `clips/<ulid>.bin` key,
// stamps `MediaPath` on the request, and then clears the inline `Content`
// field so the DB row stores only the pointer. Clients must follow
// `media_path` (D2a, shipped in cinchcli-core) to fetch the ciphertext.
//
// Skips silently for non-image clips, when no media backend is wired
// (`MEDIA_BACKEND` unset), or when the request carries empty content — in
// those cases the inline content path remains the source of truth.
//
// Free-standing (not a method on connectClipsServer) so unit tests can drive
// it with a fake media.Store without spinning up the full Connect-RPC
// handler.
func uploadImageMedia(ctx context.Context, m media.Store, req *cinchv1.PushClipRequest) error {
	if !strings.HasPrefix(req.ContentType, "image") || m == nil || req.Content == "" {
		return nil
	}
	mediaKey := "clips/" + ulid.Make().String() + ".bin"
	contentBytes := []byte(req.Content)
	if err := m.Upload(ctx, mediaKey, bytes.NewReader(contentBytes),
		int64(len(contentBytes)), "application/octet-stream"); err != nil {
		return err
	}
	mediaPath := mediaKey
	req.MediaPath = &mediaPath
	if req.ByteSize == 0 {
		req.ByteSize = int64(len(contentBytes))
	}
	// D2b cutover: once the bytes live in the media store, the inline
	// `content` column becomes dead weight (and a privacy footgun on shared
	// DB dumps). Clear it so the saved row carries only the pointer.
	req.Content = ""
	return nil
}

// ─── PushClip ────────────────────────────────────────────────

func (s *connectClipsServer) PushClip(ctx context.Context, req *connect.Request[cinchv1.PushClipRequest]) (*connect.Response[cinchv1.PushClipResponse], error) {
	userID := req.Header().Get("X-User-ID")
	if req.Msg.Content == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errMsg("content is required"))
	}

	// media_path is server-owned: strip any client-supplied value before
	// uploadImageMedia (the only path allowed to set it) so a clip can never be
	// made to reference another tenant's media key in the shared store.
	req.Msg.MediaPath = nil

	// E2EE is mandatory for non-demo users.
	isDemoUser := req.Header().Get("X-Is-Demo") == "true"
	if !isDemoUser && !req.Msg.Encrypted {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("encryption_required: server requires end-to-end encrypted clips"))
	}

	// Rate limit and storage limit check — applies to all non-demo users.
	// Fail open on DB errors so a transient blip does not block all pushes.
	if !isDemoUser {
		cap, capErr := s.h.store.GetUserCapabilities(userID)
		if capErr == nil {
			if cap.RateLimit > 0 {
				count, cntErr := s.h.store.IncrementDailyRequestCount(userID)
				if cntErr == nil && count > cap.RateLimit {
					return nil, connect.NewError(connect.CodeResourceExhausted,
						fmt.Errorf("rate_limit_exceeded: daily push limit of %d reached", cap.RateLimit))
				}
			}
			// Enforce quotas against the ACTUAL decoded content length, not the
			// client-supplied ByteSize (which a client can under-report to slip
			// past the per-user cap). Mirrors the REST PushClip handler.
			contentLen := int64(len(req.Msg.Content))
			if cap.MaxClipSizeKb > 0 {
				if contentLen > int64(cap.MaxClipSizeKb)*1024 {
					return nil, connect.NewError(connect.CodeInvalidArgument,
						fmt.Errorf("clip_too_large: maximum allowed size is %d KB", cap.MaxClipSizeKb))
				}
			}
			if cap.StorageLimitMb > 0 {
				used, usedErr := s.h.store.GetUserStorageUsage(userID)
				if usedErr == nil && used+contentLen > int64(cap.StorageLimitMb)*1024*1024 {
					return nil, connect.NewError(connect.CodeResourceExhausted,
						fmt.Errorf("storage_quota_exceeded: total storage limit of %d MB reached", cap.StorageLimitMb))
				}
			}
		}
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

	if err := uploadImageMedia(ctx, s.h.media, req.Msg); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("media upload: %w", err))
	}

	clip, isDup, err := s.h.store.SaveClip(userID, req.Msg)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	if isDemoUser {
		if err := s.h.store.IncrementDemoCounter(); err != nil {
			slog.Error("connectClipsServer.PushClip demo counter increment failed", "err", err)
		}
	}

	if req.Msg.Source != "" {
		if err := s.h.store.UpdateDeviceActivity(userID, req.Msg.Source); err != nil {
			slog.Error("connectClipsServer.PushClip device activity update failed", "err", err)
		}
	}

	if !isDup {
		delivered, sendErr := s.h.hub.SendClip(userID, clip)
		if sendErr != nil {
			slog.Error("connectClipsServer.PushClip ws broadcast failed", "user", userID, "err", sendErr)
		}
		// Loop completion: clip_send (denominator) + clip_read for every device the
		// hub delivered to over WS at push time (the push side of the loop).
		s.h.emitClipSendAndDeliveries(userID, req.Header().Get("X-Device-ID"), clip.ClipId, isDemoUser, delivered)
	}

	return connect.NewResponse(&cinchv1.PushClipResponse{
		ClipId:   clip.ClipId,
		ByteSize: clip.ByteSize,
	}), nil
}

// ─── ListClips ───────────────────────────────────────────────

func (s *connectClipsServer) ListClips(ctx context.Context, req *connect.Request[cinchv1.ListClipsRequest]) (*connect.Response[cinchv1.ListClipsResponse], error) {
	userID := req.Header().Get("X-User-ID")
	msg := req.Msg
	limit := clampLimit(int(msg.GetLimit()))

	// Backwards-compat path: when only `since` is set, preserve oldest-first replay semantics.
	if msg.GetSince() != "" && msg.GetSourceFilter() == "" && msg.GetExcludeSource() == "" && !msg.GetExcludeImage() && !msg.GetExcludeText() && len(msg.GetClipIds()) == 0 {
		sinceTime, err := time.Parse(time.RFC3339, msg.GetSince())
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, errMsg("invalid since parameter: must be RFC 3339"))
		}
		clips, err := s.h.store.ListClipsSince(userID, sinceTime, limit)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		s.h.emitClipReads(userID, req.Header().Get("X-Device-ID"), req.Header().Get("X-Is-Demo") == "true", clips)
		return connect.NewResponse(&cinchv1.ListClipsResponse{Clips: clips}), nil
	}

	clips, err := s.h.store.ListClipsFiltered(userID, ListFilter{
		Limit:         limit,
		SourceFilter:  msg.GetSourceFilter(),
		ExcludeSource: msg.GetExcludeSource(),
		ExcludeImage:  msg.GetExcludeImage(),
		ExcludeText:   msg.GetExcludeText(),
		ClipIDs:       msg.GetClipIds(),
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	s.h.emitClipReads(userID, req.Header().Get("X-Device-ID"), req.Header().Get("X-Is-Demo") == "true", clips)
	return connect.NewResponse(&cinchv1.ListClipsResponse{Clips: clips}), nil
}

// ─── GetLatestClip ───────────────────────────────────────────

func (s *connectClipsServer) GetLatestClip(ctx context.Context, req *connect.Request[cinchv1.GetLatestClipRequest]) (*connect.Response[cinchv1.GetLatestClipResponse], error) {
	userID := req.Header().Get("X-User-ID")
	msg := req.Msg

	if msg.GetSource() != "" && msg.GetExcludeSource() != "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errMsg("source and exclude_source are mutually exclusive"))
	}

	var (
		clip *cinchv1.Clip
		err  error
	)
	switch {
	case msg.GetExcludeSource() != "":
		clip, err = s.h.store.GetLatestClipExcludingSource(userID, msg.GetExcludeSource())
	case msg.GetSource() != "":
		clip, err = s.h.store.GetLatestClipBySource(userID, msg.GetSource())
	default:
		clip, err = s.h.store.GetLatestClipForUser(userID)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil, connect.NewError(connect.CodeNotFound, errMsg("no matching clip"))
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}
	// Loop-completion numerator: a device read a clip (cross-device counted in the
	// dashboard via device_ref).
	s.h.emitClipRead(userID, req.Header().Get("X-Device-ID"), clip.ClipId, req.Header().Get("X-Is-Demo") == "true")
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
		slog.Error("InsertTombstone failed", "clip_id", req.Msg.ClipId, "err", err)
	}
	s.h.hub.SendClipDeleted(userID, req.Msg.ClipId)
	return connect.NewResponse(&cinchv1.DeleteClipResponse{Ok: true}), nil
}

// defaultConnectReadMaxBytes bounds the decoded size of a single Connect-RPC
// request message. It is generous enough for an inline-encrypted clipboard
// image (the REST binary path caps uploads at 20 MiB) plus framing/encryption
// overhead, while stopping a client from streaming a multi-gigabyte message to
// OOM the relay. connect-go's own default is 0 = unlimited.
const defaultConnectReadMaxBytes = 64 << 20 // 64 MiB

// connectReadMax returns the configured per-message read cap, falling back to
// defaultConnectReadMaxBytes. It never returns 0 (which connect-go treats as
// unlimited), so forgetting to set the field still yields a bounded handler.
func (h *Handler) connectReadMax() int {
	if h.ConnectReadMaxBytes > 0 {
		return h.ConnectReadMaxBytes
	}
	return defaultConnectReadMaxBytes
}

// newClipsConnectHandler wraps the Connect ClipsService handler with auth interceptor.
func (h *Handler) newClipsConnectHandler() (string, http.Handler) {
	return cinchv1connect.NewClipsServiceHandler(
		&connectClipsServer{h: h},
		connect.WithInterceptors(h.clipsConnectInterceptor()),
		connect.WithReadMaxBytes(h.connectReadMax()),
	)
}
