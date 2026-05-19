package relay

import (
	"context"
	"net/http"

	"connectrpc.com/connect"

	cinchv1 "github.com/cinchcli/cinch-core/go/cinch/v1"
	"github.com/cinchcli/cinch-core/go/cinch/v1/cinchv1connect"
)

type connectEventsServer struct {
	h *Handler
}

var _ cinchv1connect.EventStreamServiceHandler = (*connectEventsServer)(nil)

// ─── Subscribe ───────────────────────────────────────────────

func (s *connectEventsServer) Subscribe(
	ctx context.Context,
	req *connect.Request[cinchv1.SubscribeRequest],
	stream *connect.ServerStream[cinchv1.ServerEvent],
) error {
	userID := req.Header().Get("X-User-ID")
	deviceID := req.Header().Get("X-Device-ID")
	if deviceID == "" {
		return connect.NewError(connect.CodeUnauthenticated, errMsg("per-device token required for event stream"))
	}

	ch := s.h.hub.RegisterEventSub(userID, deviceID)
	defer s.h.hub.UnregisterEventSub(userID, deviceID)

	// Notify pending key exchanges for devices that paired while this device was offline.
	go func() {
		pending, err := s.h.store.ListPendingKeyExchanges(userID)
		if err != nil {
			return
		}
		for _, d := range pending {
			s.h.hub.sendToEventSub(userID, deviceID, &cinchv1.ServerEvent{
				Event: &cinchv1.ServerEvent_KeyExchange{
					KeyExchange: &cinchv1.KeyExchangeEvent{
						DeviceId:             d.Id,
						Hostname:             d.Hostname,
						DeviceKeyFingerprint: d.PublicKeyFingerprint,
					},
				},
			})
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case event, ok := <-ch:
			if !ok {
				// Channel closed — a new connection for this device replaced this one.
				return nil
			}
			if event == nil {
				continue
			}
			if err := stream.Send(event); err != nil {
				return err
			}
		}
	}
}

// eventsAuthInterceptor applies auth for both unary calls and server-streaming Subscribe.
// UnaryInterceptorFunc only covers unary calls, so a full Interceptor is needed here.
type eventsAuthInterceptor struct{ h *Handler }

func (i *eventsAuthInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if err := i.h.requireConnectAuth(req); err != nil {
			return nil, err
		}
		return next(ctx, req)
	}
}

func (i *eventsAuthInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next // relay is server-side only
}

func (i *eventsAuthInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		if err := i.h.requireConnectAuthHeaders(conn.RequestHeader()); err != nil {
			return err
		}
		return next(ctx, conn)
	}
}

// newEventsConnectHandler returns the mounted EventStreamService handler.
func (h *Handler) newEventsConnectHandler() (string, http.Handler) {
	return cinchv1connect.NewEventStreamServiceHandler(
		&connectEventsServer{h: h},
		connect.WithInterceptors(&eventsAuthInterceptor{h: h}),
	)
}
