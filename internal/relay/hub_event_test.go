package relay

import (
	"testing"
	"time"

	cinchv1 "github.com/cinchcli/relay/internal/gen/cinch/v1"
)

func TestEventSub_ReceivesServerEventDirectly(t *testing.T) {
	h := NewHub()

	ch := h.RegisterEventSub("user1", "device1")

	want := &cinchv1.ServerEvent{
		Event: &cinchv1.ServerEvent_NewClip{
			NewClip: &cinchv1.NewClipEvent{
				Clip: &cinchv1.Clip{ClipId: "c1", Content: "hello"},
			},
		},
	}
	h.sendToEventSub("user1", "device1", want)

	select {
	case got := <-ch:
		if got != want {
			t.Fatalf("got %v, want %v", got, want)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout: no event received")
	}
}

func TestEventSub_SendToUser_FansOut(t *testing.T) {
	h := NewHub()

	ch1 := h.RegisterEventSub("user1", "device1")
	ch2 := h.RegisterEventSub("user1", "device2")

	event := &cinchv1.ServerEvent{
		Event: &cinchv1.ServerEvent_Revoked{
			Revoked: &cinchv1.RevokedEvent{Reason: "test"},
		},
	}
	h.SendToUser("user1", event)

	for _, ch := range []<-chan *cinchv1.ServerEvent{ch1, ch2} {
		select {
		case got := <-ch:
			if got != event {
				t.Fatalf("got %v, want %v", got, event)
			}
		case <-time.After(100 * time.Millisecond):
			t.Fatal("timeout: no event received on one of the channels")
		}
	}
}

func TestEventSub_UnregisterClosesChannel(t *testing.T) {
	h := NewHub()
	ch := h.RegisterEventSub("user1", "device1")
	h.UnregisterEventSub("user1", "device1")

	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("expected channel to be closed")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout: channel not closed after unregister")
	}
}
