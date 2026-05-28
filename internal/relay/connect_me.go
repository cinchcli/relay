package relay

import (
	"context"
	"net/http"

	"connectrpc.com/connect"

	cinchv1 "github.com/cinchcli/relay/internal/cinchv1"
	"github.com/cinchcli/relay/internal/cinchv1/cinchv1connect"
)

// Hosted relay device-limit constants. The relay encodes the public self-serve
// plan identity in the DeviceLimit cap until user_capabilities gains an
// explicit plan_name column.
//
// TODO: replace heuristic with a plan_name column on user_capabilities so
// the relay isn't inferring plan identity from one cap and so we can
// distinguish self-host (no row) from paid/custom accounts.
const (
	freeDeviceLimit = 3
	proDeviceLimit  = 10
)

// connectMeServer implements cinchv1connect.MeServiceHandler. Exposes the
// caller's plan caps + current usage so the CLI / desktop can render plan
// state without scraping the legacy /internal/users endpoint.
type connectMeServer struct {
	h *Handler
}

var _ cinchv1connect.MeServiceHandler = (*connectMeServer)(nil)

// GetMe returns the caller's plan + usage. Auth is enforced by the
// shared clipsConnectInterceptor, which sets X-User-ID on the request
// headers. A defensive empty-check stays here so the handler still
// fails closed if the interceptor is ever bypassed.
func (s *connectMeServer) GetMe(ctx context.Context, req *connect.Request[cinchv1.GetMeRequest]) (*connect.Response[cinchv1.GetMeResponse], error) {
	userID := req.Header().Get("X-User-ID")
	if userID == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated, errMsg("auth required"))
	}

	cap, err := s.h.store.GetUserCapabilities(userID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	active, err := s.h.store.CountActiveDevices(userID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&cinchv1.GetMeResponse{
		PlanName: planNameFromCaps(cap),
		Plan: &cinchv1.Plan{
			DeviceLimit:   int32(cap.DeviceLimit),
			RetentionDays: int32(cap.RetentionDays),
			RateLimit:     int32(cap.RateLimit),
		},
		Usage: &cinchv1.Usage{
			ActiveDevices: int32(active),
		},
	}), nil
}

// planNameFromCaps derives a human-readable plan name from caps. The relay
// owns the mapping so clients don't have to. "free" is the default for
// users with no user_capabilities row; explicit caps are inferred from the
// device_limit. Any cap shape the server hasn't named yet is reported as
// "custom" so commercial/private-hosting accounts don't imply a self-serve
// team product that does not exist yet.
func planNameFromCaps(cap UserCapabilities) string {
	switch cap.DeviceLimit {
	case 0:
		if cap.RetentionDays == 0 && cap.RateLimit == 0 {
			return "free"
		}
		return "custom"
	case freeDeviceLimit:
		return "free"
	case proDeviceLimit:
		return "pro"
	default:
		return "custom"
	}
}

// newMeConnectHandler wraps MeService with the shared auth interceptor so
// every procedure sees a resolved X-User-ID header.
func (h *Handler) newMeConnectHandler() (string, http.Handler) {
	return cinchv1connect.NewMeServiceHandler(
		&connectMeServer{h: h},
		connect.WithInterceptors(h.clipsConnectInterceptor()),
	)
}
