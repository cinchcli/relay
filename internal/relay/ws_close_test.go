package relay

import (
	"errors"
	"io"
	"testing"

	"github.com/gorilla/websocket"
)

func TestShouldLogWSClose(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"1000 normal closure", &websocket.CloseError{Code: websocket.CloseNormalClosure}, false},
		{"1001 going away", &websocket.CloseError{Code: websocket.CloseGoingAway}, false},
		{"1006 abnormal (proxy idle / NAT / client death)", &websocket.CloseError{Code: websocket.CloseAbnormalClosure}, false},
		{"1002 protocol error (should log)", &websocket.CloseError{Code: websocket.CloseProtocolError}, true},
		{"1011 internal server error (should log)", &websocket.CloseError{Code: websocket.CloseInternalServerErr}, true},
		{"1008 policy violation (should log)", &websocket.CloseError{Code: websocket.ClosePolicyViolation}, true},
		// Non-CloseError errors: IsUnexpectedCloseError returns false for these,
		// so the predicate also returns false — they go unlogged. This matches
		// the original behavior; the ws read loop just falls through and
		// returns. If you ever want to log raw read errors, change here.
		{"io.EOF (raw read error)", io.EOF, false},
		{"opaque error", errors.New("boom"), false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldLogWSClose(tc.err); got != tc.want {
				t.Errorf("shouldLogWSClose(%T{%v}) = %v, want %v", tc.err, tc.err, got, tc.want)
			}
		})
	}
}
