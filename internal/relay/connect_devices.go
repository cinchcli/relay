package relay

import (
	"context"
	"errors"
	"net/http"

	"connectrpc.com/connect"

	cinchv1 "github.com/cinchcli/relay/internal/cinchv1"
	"github.com/cinchcli/relay/internal/cinchv1/cinchv1connect"
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
	return errors.Is(err, ErrRetentionOutOfRange)
}

// newDevicesConnectHandler wraps DevicesService with auth interceptor.
func (h *Handler) newDevicesConnectHandler() (string, http.Handler) {
	return cinchv1connect.NewDevicesServiceHandler(
		&connectDevicesServer{h: h},
		connect.WithInterceptors(h.clipsConnectInterceptor()),
	)
}
