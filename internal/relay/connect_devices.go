package relay

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"

	cinchv1 "github.com/cinchcli/relay/internal/gen/cinch/v1"
	"github.com/cinchcli/relay/internal/gen/cinch/v1/cinchv1connect"
)

type connectDevicesServer struct {
	h *Handler
}

var _ cinchv1connect.DevicesServiceHandler = (*connectDevicesServer)(nil)

// ─── ListDevices ─────────────────────────────────────────────

func (s *connectDevicesServer) ListDevices(ctx context.Context, req *connect.Request[cinchv1.ListDevicesRequest]) (*connect.Response[cinchv1.ListDevicesResponse], error) {
	userID := req.Header().Get("X-User-ID")
	devices, err := s.h.store.ListDevices(userID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	// `online` isn't a stored column — it's a runtime hub query — so the
	// store leaves it false and we fill it in here per device.
	for _, d := range devices {
		d.Online = s.h.hub.IsDeviceOnline(userID, d.Id)
	}
	return connect.NewResponse(&cinchv1.ListDevicesResponse{Devices: devices}), nil
}

// ─── SetNickname ─────────────────────────────────────────────

func (s *connectDevicesServer) SetNickname(ctx context.Context, req *connect.Request[cinchv1.SetNicknameRequest]) (*connect.Response[cinchv1.SetNicknameResponse], error) {
	callerUserID := req.Header().Get("X-User-ID")
	if req.Msg.DeviceId == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errMsg("device_id is required"))
	}
	if len([]rune(req.Msg.Nickname)) > 32 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errMsg("nickname must be 32 characters or fewer"))
	}

	ownerID, err := s.h.store.DeviceOwner(req.Msg.DeviceId)
	if err != nil || ownerID != callerUserID {
		return nil, connect.NewError(connect.CodeNotFound, errMsg("device not found"))
	}

	if err := s.h.store.SetDeviceNickname(req.Msg.DeviceId, req.Msg.Nickname); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&cinchv1.SetNicknameResponse{Ok: true}), nil
}

// ─── SetRetention ────────────────────────────────────────────

func (s *connectDevicesServer) SetRetention(ctx context.Context, req *connect.Request[cinchv1.SetRetentionRequest]) (*connect.Response[cinchv1.SetRetentionResponse], error) {
	deviceID := req.Header().Get("X-Device-ID")
	if deviceID == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated, errMsg("per-device token required for retention update"))
	}

	if err := s.h.store.UpdateDeviceRetention(deviceID, int(req.Msg.RemoteRetentionDays)); err != nil {
		if isRangeError(err) {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&cinchv1.SetRetentionResponse{Ok: true}), nil
}

func isRangeError(err error) bool {
	return strings.Contains(err.Error(), "between 1 and 365")
}

// ─── Pull ────────────────────────────────────────────────────

func (s *connectDevicesServer) Pull(ctx context.Context, req *connect.Request[cinchv1.PullRequest]) (*connect.Response[cinchv1.PullResponse], error) {
	userID := req.Header().Get("X-User-ID")

	if isDemo, _ := s.h.store.IsDemoUser(userID); isDemo {
		return nil, connect.NewError(connect.CodePermissionDenied, errMsg("demo sessions cannot pull from a desktop agent"))
	}

	pullID := ulid.Make().String()
	content, err := s.h.hub.RequestClipboard(userID, pullID)
	if err != nil {
		switch {
		case errors.Is(err, ErrAgentOffline):
			return nil, connect.NewError(connect.CodeUnavailable, errMsg("desktop agent is not connected"))
		case errors.Is(err, ErrAgentTimeout):
			return nil, connect.NewError(connect.CodeDeadlineExceeded, errMsg("desktop agent did not respond within 10 seconds"))
		default:
			return nil, connect.NewError(connect.CodeInternal, err)
		}
	}

	return connect.NewResponse(&cinchv1.PullResponse{
		PullId:  pullID,
		Content: content,
	}), nil
}

// newDevicesConnectHandler wraps DevicesService with auth interceptor.
func (h *Handler) newDevicesConnectHandler() (string, http.Handler) {
	return cinchv1connect.NewDevicesServiceHandler(
		&connectDevicesServer{h: h},
		connect.WithInterceptors(h.clipsConnectInterceptor()),
	)
}
