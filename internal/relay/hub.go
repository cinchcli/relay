package relay

import (
	"log/slog"
	"sync"
	"time"

	cinchv1 "github.com/cinchcli/relay/internal/cinchv1"
	"github.com/cinchcli/relay/internal/protocol"
	"github.com/gorilla/websocket"
)

// Hub manages WebSocket connections keyed by (user_id, device_id).
type Hub struct {
	mu    sync.RWMutex
	conns map[string]map[string]*AgentConn // userID -> deviceID -> conn

	// eventSubs are Connect-RPC streaming subscribers (parallel to WS conns).
	// Keyed by userID -> deviceID; fan-out mirrors the WS path.
	eventSubsMu sync.RWMutex
	eventSubs   map[string]map[string]chan *cinchv1.ServerEvent
}

// AgentConn wraps a WebSocket connection for one desktop agent.
//
// Lifecycle ownership: exactly one writer goroutine drains send and writes to
// the socket. Teardown (close the socket, stop the writer) is funnelled through
// stop(), guarded by stopOnce so the three triggers — a replacing Register, a
// Remove, and heartbeat eviction — can all fire without double-closing. The
// send channel is deliberately never closed; broadcasters select on done so a
// teardown in flight can never turn into a send on a closed channel.
type AgentConn struct {
	UserID   string
	DeviceID string
	Conn     *websocket.Conn
	send     chan protocol.WSMessage

	key      string // map key under conns[UserID]; deviceID, or userID for legacy
	done     chan struct{}
	stopOnce sync.Once
}

// stop signals the writer to exit and closes the socket. Idempotent.
func (ac *AgentConn) stop() {
	ac.stopOnce.Do(func() {
		close(ac.done)
		ac.Conn.Close()
	})
}

// trySend enqueues msg without blocking. It drops the message if the buffer is
// full (slow/dead consumer) or the connection is being torn down. Reports
// whether the message was enqueued. Safe against concurrent stop(): send never
// races a channel close because send is never closed.
func (ac *AgentConn) trySend(msg protocol.WSMessage) bool {
	select {
	case ac.send <- msg:
		return true
	case <-ac.done:
		return false
	default:
		return false
	}
}

func (ac *AgentConn) writer() {
	for {
		select {
		case <-ac.done:
			return
		case msg := <-ac.send:
			// Set a write deadline to prevent slow connections from lingering.
			ac.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := ac.Conn.WriteJSON(msg); err != nil {
				slog.Warn("ws write failed", "user", short(ac.UserID), "device", short(ac.DeviceID), "err", err)
				ac.stop()
				return
			}
		}
	}
}

// short returns the first 8 runes of an id for log lines, tolerating ids
// shorter than 8 characters (legacy/short device ids must not panic).
func short(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}

// serverEventToWSMessage converts a ServerEvent to a WSMessage for legacy WS delivery.
// Returns nil for unknown or nil events.
func serverEventToWSMessage(e *cinchv1.ServerEvent) *protocol.WSMessage {
	if e == nil {
		return nil
	}
	switch ev := e.Event.(type) {
	case *cinchv1.ServerEvent_NewClip:
		return &protocol.WSMessage{Action: protocol.ActionNewClip, Clip: ev.NewClip.Clip}
	case *cinchv1.ServerEvent_Revoked:
		return &protocol.WSMessage{Action: protocol.ActionRevoked, Reason: ev.Revoked.Reason}
	case *cinchv1.ServerEvent_TokenRotated:
		return &protocol.WSMessage{
			Action:   protocol.ActionTokenRotated,
			Token:    ev.TokenRotated.Token,
			DeviceID: ev.TokenRotated.DeviceId,
			Hostname: ev.TokenRotated.Hostname,
		}
	case *cinchv1.ServerEvent_KeyExchange:
		return &protocol.WSMessage{
			Action:               protocol.ActionKeyExchangeRequested,
			DeviceID:             ev.KeyExchange.DeviceId,
			Hostname:             ev.KeyExchange.Hostname,
			DeviceKeyFingerprint: ev.KeyExchange.DeviceKeyFingerprint,
		}
	case *cinchv1.ServerEvent_ClipDeleted:
		return &protocol.WSMessage{
			Action: protocol.ActionClipDeleted,
			Clip:   &cinchv1.Clip{ClipId: ev.ClipDeleted.ClipId},
		}
	case *cinchv1.ServerEvent_ClipPinned:
		return &protocol.WSMessage{
			Action: protocol.ActionClipPinned,
			Clip: &cinchv1.Clip{
				ClipId:   ev.ClipPinned.ClipId,
				IsPinned: ev.ClipPinned.IsPinned,
				PinNote:  ev.ClipPinned.PinNote,
			},
		}
	default:
		return nil
	}
}

func NewHub() *Hub {
	return &Hub{
		conns:     make(map[string]map[string]*AgentConn),
		eventSubs: make(map[string]map[string]chan *cinchv1.ServerEvent),
	}
}

// RegisterEventSub registers a Connect-RPC streaming subscriber for (userID, deviceID).
// Returns a receive-only channel that receives ServerEvent events until the subscriber
// calls UnregisterEventSub or the channel is closed on a duplicate registration.
func (h *Hub) RegisterEventSub(userID, deviceID string) <-chan *cinchv1.ServerEvent {
	ch := make(chan *cinchv1.ServerEvent, 64)
	h.eventSubsMu.Lock()
	if h.eventSubs[userID] == nil {
		h.eventSubs[userID] = make(map[string]chan *cinchv1.ServerEvent)
	}
	if old, ok := h.eventSubs[userID][deviceID]; ok {
		close(old)
	}
	h.eventSubs[userID][deviceID] = ch
	h.eventSubsMu.Unlock()
	slog.Info("event stream connected", "user", userID[:min(8, len(userID))], "device", deviceID[:min(8, len(deviceID))])
	return ch
}

// UnregisterEventSub removes and closes the event channel for (userID, deviceID).
func (h *Hub) UnregisterEventSub(userID, deviceID string) {
	h.eventSubsMu.Lock()
	if devs, ok := h.eventSubs[userID]; ok {
		if ch, ok := devs[deviceID]; ok {
			close(ch)
			delete(devs, deviceID)
			slog.Info("event stream disconnected", "user", userID[:min(8, len(userID))], "device", deviceID[:min(8, len(deviceID))])
		}
		if len(devs) == 0 {
			delete(h.eventSubs, userID)
		}
	}
	h.eventSubsMu.Unlock()
}

// sendToEventSubs fans an event out to all event stream subscribers for userID.
// Non-blocking per subscriber; drops on full to avoid stalling.
// The non-blocking sends below run while holding the read lock. Closing a
// subscriber channel (RegisterEventSub replacement, UnregisterEventSub) requires
// the write lock, so it cannot race an in-flight send — eliminating the
// send-on-closed-channel window that a copy-then-release approach left open.
// The sends never block (select default), so holding the read lock is cheap.
func (h *Hub) sendToEventSubs(userID string, event *cinchv1.ServerEvent) {
	h.eventSubsMu.RLock()
	defer h.eventSubsMu.RUnlock()
	for _, ch := range h.eventSubs[userID] {
		select {
		case ch <- event:
		default:
			slog.Warn("event sub buffer full for user", "user", short(userID))
		}
	}
}

// sendToEventSub fans an event to a specific (userID, deviceID) event subscriber.
func (h *Hub) sendToEventSub(userID, deviceID string, event *cinchv1.ServerEvent) {
	h.eventSubsMu.RLock()
	defer h.eventSubsMu.RUnlock()
	ch := h.eventSubs[userID][deviceID]
	if ch == nil {
		return
	}
	select {
	case ch <- event:
	default:
		slog.Warn("event sub buffer full for device", "device", short(deviceID))
	}
}

// Run starts the hub's background tasks (heartbeat cleanup).
func (h *Hub) Run() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		// Copy conn list while holding read lock to avoid holding across channel sends.
		h.mu.RLock()
		type connEntry struct {
			uid string
			did string
			ac  *AgentConn
		}
		var all []connEntry
		for uid, devs := range h.conns {
			for did, ac := range devs {
				all = append(all, connEntry{uid, did, ac})
			}
		}
		h.mu.RUnlock()

		for _, e := range all {
			if !e.ac.trySend(protocol.WSMessage{Action: protocol.ActionPing}) {
				slog.Warn("heartbeat dropped, buffer full", "user", short(e.uid))
				// Connection is likely dead or extremely slow. Evict the
				// specific conn we hold, never whatever replaced it.
				h.RemoveConn(e.ac)
			}
		}
	}
}

// Register adds an agent connection keyed by (userID, deviceID) and returns the
// AgentConn so the caller's read loop can tear down exactly the conn it owns
// (via RemoveConn). If deviceID is empty (legacy master-token path), the userID
// is used as the fallback key.
func (h *Hub) Register(userID, deviceID string, conn *websocket.Conn) *AgentConn {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.conns[userID] == nil {
		h.conns[userID] = make(map[string]*AgentConn)
	}
	key := deviceID
	if key == "" {
		key = userID // legacy fallback key for pre-Phase-2 agents
	}
	// If this (user, device) already has a conn, tear it down — new conn wins.
	if old, ok := h.conns[userID][key]; ok {
		old.stop()
	}
	ac := &AgentConn{
		UserID:   userID,
		DeviceID: deviceID,
		Conn:     conn,
		send:     make(chan protocol.WSMessage, 64),
		key:      key,
		done:     make(chan struct{}),
	}
	h.conns[userID][key] = ac
	go ac.writer()
	slog.Info("agent connected", "user", short(userID), "device", short(key))
	return ac
}

// RemoveConn tears down and removes ac, but only if it is still the registered
// connection for its key. This ownership check is what prevents a stale read
// loop (whose conn was already replaced by a reconnect) from evicting the live
// replacement. Always stops ac so its socket and writer are released.
func (h *Hub) RemoveConn(ac *AgentConn) {
	if ac == nil {
		return
	}
	ac.stop()

	h.mu.Lock()
	defer h.mu.Unlock()
	devs, ok := h.conns[ac.UserID]
	if !ok {
		return
	}
	if cur, ok := devs[ac.key]; ok && cur == ac {
		delete(devs, ac.key)
		slog.Info("agent disconnected", "user", short(ac.UserID), "device", short(ac.key))
		if len(devs) == 0 {
			delete(h.conns, ac.UserID)
		}
	}
}

// Remove disconnects and removes whatever connection is currently registered
// for (userID, deviceID). Prefer RemoveConn when the caller holds the specific
// AgentConn; this variant is for callers that only know the key.
func (h *Hub) Remove(userID, deviceID string) {
	h.mu.Lock()
	key := deviceID
	if key == "" {
		key = userID
	}
	var ac *AgentConn
	if devs, ok := h.conns[userID]; ok {
		ac = devs[key]
	}
	h.mu.Unlock()
	h.RemoveConn(ac)
}

// SendClip broadcasts a new clip to all connected devices of the user (fan-out).
// Delivers to both WS conns and Connect event stream subscribers.
func (h *Hub) SendClip(userID string, clip *cinchv1.Clip) error {
	h.mu.RLock()
	devs := h.conns[userID]
	conns := make([]*AgentConn, 0, len(devs))
	for _, ac := range devs {
		conns = append(conns, ac)
	}
	h.mu.RUnlock()

	wsMsg := protocol.WSMessage{Action: protocol.ActionNewClip, Clip: clip}
	event := &cinchv1.ServerEvent{
		Event: &cinchv1.ServerEvent_NewClip{
			NewClip: &cinchv1.NewClipEvent{Clip: clip},
		},
	}

	for _, ac := range conns {
		if !ac.trySend(wsMsg) {
			slog.Warn("ws broadcast dropped, buffer full", "user", short(userID), "device", short(ac.DeviceID))
		}
	}

	h.sendToEventSubs(userID, event)
	return nil
}

// SendClipDeleted broadcasts a clip_deleted event to all connected devices of the user.
// Delivers to both WS conns and Connect event stream subscribers.
func (h *Hub) SendClipDeleted(userID, clipID string) {
	h.mu.RLock()
	devs := h.conns[userID]
	conns := make([]*AgentConn, 0, len(devs))
	for _, ac := range devs {
		conns = append(conns, ac)
	}
	h.mu.RUnlock()

	wsMsg := protocol.WSMessage{
		Action: protocol.ActionClipDeleted,
		Clip:   &cinchv1.Clip{ClipId: clipID},
	}
	event := &cinchv1.ServerEvent{
		Event: &cinchv1.ServerEvent_ClipDeleted{
			ClipDeleted: &cinchv1.ClipDeletedEvent{ClipId: clipID},
		},
	}

	for _, ac := range conns {
		if !ac.trySend(wsMsg) {
			slog.Warn("SendClipDeleted dropped", "device", short(ac.DeviceID))
		}
	}

	h.sendToEventSubs(userID, event)
}

// SendClipPinned broadcasts a clip_pinned event to all connected devices of the user.
// Delivers to both WS conns and Connect event stream subscribers.
func (h *Hub) SendClipPinned(userID, clipID string, isPinned bool, pinNote *string) {
	h.mu.RLock()
	devs := h.conns[userID]
	conns := make([]*AgentConn, 0, len(devs))
	for _, ac := range devs {
		conns = append(conns, ac)
	}
	h.mu.RUnlock()

	wsMsg := protocol.WSMessage{
		Action: protocol.ActionClipPinned,
		Clip:   &cinchv1.Clip{ClipId: clipID, IsPinned: isPinned, PinNote: pinNote},
	}
	event := &cinchv1.ServerEvent{
		Event: &cinchv1.ServerEvent_ClipPinned{
			ClipPinned: &cinchv1.ClipPinnedEvent{ClipId: clipID, IsPinned: isPinned, PinNote: pinNote},
		},
	}

	for _, ac := range conns {
		if !ac.trySend(wsMsg) {
			slog.Warn("SendClipPinned dropped", "device", short(ac.DeviceID))
		}
	}

	h.sendToEventSubs(userID, event)
}

// BroadcastWSToUser fans a pre-built WSMessage out to every connected
// WS device of userID. Generic counterpart to SendClip for non-clip
// payloads (device_code_pending, future broadcast types). WS-only —
// does not mirror to Connect-RPC event subs.
func (h *Hub) BroadcastWSToUser(userID string, msg *protocol.WSMessage) {
	h.mu.RLock()
	devs := h.conns[userID]
	conns := make([]*AgentConn, 0, len(devs))
	for _, ac := range devs {
		conns = append(conns, ac)
	}
	h.mu.RUnlock()

	for _, ac := range conns {
		if !ac.trySend(*msg) {
			slog.Warn("BroadcastWSToUser dropped", "user", userID, "device", short(ac.DeviceID))
		}
	}
}

// SendToUser sends an event to all connected devices for a user (WS + event stream).
func (h *Hub) SendToUser(userID string, event *cinchv1.ServerEvent) {
	h.mu.RLock()
	devs := h.conns[userID]
	// Copy to avoid holding the lock during WriteJSON calls.
	conns := make([]*AgentConn, 0, len(devs))
	for _, ac := range devs {
		conns = append(conns, ac)
	}
	h.mu.RUnlock()

	if wsMsg := serverEventToWSMessage(event); wsMsg != nil {
		for _, ac := range conns {
			if !ac.trySend(*wsMsg) {
				slog.Warn("SendToUser dropped", "device", short(ac.DeviceID))
			}
		}
	}

	h.sendToEventSubs(userID, event)
}

// SendToDevice pushes an event to the specific (userID, deviceID) connection if present.
// Checks WS conn first, then event stream subscriber.
// Returns nil if the device is offline — revoke/rotation is server-authoritative;
// clients discover state on next HTTP request regardless of delivery.
func (h *Hub) SendToDevice(userID, deviceID string, event *cinchv1.ServerEvent) error {
	h.mu.RLock()
	var ac *AgentConn
	if devs, ok := h.conns[userID]; ok {
		ac = devs[deviceID]
	}
	h.mu.RUnlock()

	if ac != nil {
		wsMsg := serverEventToWSMessage(event)
		if wsMsg == nil {
			return nil
		}
		if !ac.trySend(*wsMsg) {
			slog.Warn("SendToDevice dropped", "device", short(deviceID))
		}
		return nil
	}

	h.sendToEventSub(userID, deviceID, event)
	return nil
}

// IsDeviceOnline checks if a specific (userID, deviceID) connection is active (WS or event stream).
func (h *Hub) IsDeviceOnline(userID, deviceID string) bool {
	h.mu.RLock()
	if devs, ok := h.conns[userID]; ok {
		if _, ok := devs[deviceID]; ok {
			h.mu.RUnlock()
			return true
		}
	}
	h.mu.RUnlock()

	h.eventSubsMu.RLock()
	defer h.eventSubsMu.RUnlock()
	if devs, ok := h.eventSubs[userID]; ok {
		_, ok := devs[deviceID]
		return ok
	}
	return false
}

// IsOnline checks if any device of the user's desktop agent is connected (WS or event stream).
func (h *Hub) IsOnline(userID string) bool {
	h.mu.RLock()
	devs, ok := h.conns[userID]
	wsOk := ok && len(devs) > 0
	h.mu.RUnlock()
	if wsOk {
		return true
	}
	h.eventSubsMu.RLock()
	defer h.eventSubsMu.RUnlock()
	devs2, ok2 := h.eventSubs[userID]
	return ok2 && len(devs2) > 0
}

// HandleAgentMessage processes messages from the agent's WebSocket.
func (h *Hub) HandleAgentMessage(msg *protocol.WSMessage) {
	switch msg.Action {
	case protocol.ActionPong:
		// heartbeat response, nothing to do
	}
}
