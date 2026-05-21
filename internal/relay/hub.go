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
type AgentConn struct {
	UserID   string
	DeviceID string // Phase 2: required for device-keyed routing
	Conn     *websocket.Conn
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
func (h *Hub) sendToEventSubs(userID string, event *cinchv1.ServerEvent) {
	h.eventSubsMu.RLock()
	devs := h.eventSubs[userID]
	if len(devs) == 0 {
		h.eventSubsMu.RUnlock()
		return
	}
	chs := make([]chan *cinchv1.ServerEvent, 0, len(devs))
	for _, ch := range devs {
		chs = append(chs, ch)
	}
	h.eventSubsMu.RUnlock()

	for _, ch := range chs {
		select {
		case ch <- event:
		default:
			slog.Warn("event sub buffer full for user", "user", userID[:8])
		}
	}
}

// sendToEventSub fans an event to a specific (userID, deviceID) event subscriber.
func (h *Hub) sendToEventSub(userID, deviceID string, event *cinchv1.ServerEvent) {
	h.eventSubsMu.RLock()
	var ch chan *cinchv1.ServerEvent
	if devs, ok := h.eventSubs[userID]; ok {
		ch = devs[deviceID]
	}
	h.eventSubsMu.RUnlock()
	if ch == nil {
		return
	}
	select {
	case ch <- event:
	default:
		slog.Warn("event sub buffer full for device", "device", deviceID[:8])
	}
}

// Run starts the hub's background tasks (heartbeat cleanup).
func (h *Hub) Run() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		// Copy conn list while holding read lock to avoid holding across WriteJSON.
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
			if err := e.ac.Conn.WriteJSON(protocol.WSMessage{Action: protocol.ActionPing}); err != nil {
				slog.Warn("heartbeat failed", "user", e.uid[:8], "err", err)
				// Guard against reconnect race: only remove if the conn pointer still matches.
				// A new Register() call between the snapshot and here replaces the pointer;
				// removing by key alone would evict the newly-registered connection instead.
				h.mu.Lock()
				if devs, ok := h.conns[e.uid]; ok {
					key := e.did
					if key == "" {
						key = e.uid
					}
					if existing, ok := devs[key]; ok && existing == e.ac {
						existing.Conn.Close()
						delete(devs, key)
					}
				}
				h.mu.Unlock()
			}
		}
	}
}

// Register adds an agent connection keyed by (userID, deviceID).
// If deviceID is empty (legacy master-token path), use the userID as a fallback key.
func (h *Hub) Register(userID, deviceID string, conn *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.conns[userID] == nil {
		h.conns[userID] = make(map[string]*AgentConn)
	}
	key := deviceID
	if key == "" {
		key = userID // legacy fallback key for pre-Phase-2 agents
	}
	// If this (user, device) already has a conn, close it — new conn wins.
	if old, ok := h.conns[userID][key]; ok {
		old.Conn.Close()
	}
	h.conns[userID][key] = &AgentConn{UserID: userID, DeviceID: deviceID, Conn: conn}
	slog.Info("agent connected", "user", userID[:8], "device", key[:8])
}

// Remove disconnects and removes a specific (userID, deviceID) connection.
func (h *Hub) Remove(userID, deviceID string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if devs, ok := h.conns[userID]; ok {
		key := deviceID
		if key == "" {
			key = userID
		}
		if ac, ok := devs[key]; ok {
			ac.Conn.Close()
			delete(devs, key)
			slog.Info("agent disconnected", "user", userID[:8], "device", key[:8])
		}
		if len(devs) == 0 {
			delete(h.conns, userID)
		}
	}
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

	wsMsg := &protocol.WSMessage{Action: protocol.ActionNewClip, Clip: clip}
	event := &cinchv1.ServerEvent{
		Event: &cinchv1.ServerEvent_NewClip{
			NewClip: &cinchv1.NewClipEvent{Clip: clip},
		},
	}

	var firstErr error
	for _, ac := range conns {
		if err := ac.Conn.WriteJSON(wsMsg); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	h.sendToEventSubs(userID, event)
	return firstErr
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

	wsMsg := &protocol.WSMessage{
		Action: protocol.ActionClipDeleted,
		Clip:   &cinchv1.Clip{ClipId: clipID},
	}
	event := &cinchv1.ServerEvent{
		Event: &cinchv1.ServerEvent_ClipDeleted{
			ClipDeleted: &cinchv1.ClipDeletedEvent{ClipId: clipID},
		},
	}

	for _, ac := range conns {
		if err := ac.Conn.WriteJSON(wsMsg); err != nil {
			slog.Warn("SendClipDeleted write error", "device", ac.DeviceID, "err", err)
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

	wsMsg := &protocol.WSMessage{
		Action: protocol.ActionClipPinned,
		Clip:   &cinchv1.Clip{ClipId: clipID, IsPinned: isPinned, PinNote: pinNote},
	}
	event := &cinchv1.ServerEvent{
		Event: &cinchv1.ServerEvent_ClipPinned{
			ClipPinned: &cinchv1.ClipPinnedEvent{ClipId: clipID, IsPinned: isPinned, PinNote: pinNote},
		},
	}

	for _, ac := range conns {
		if err := ac.Conn.WriteJSON(wsMsg); err != nil {
			slog.Warn("SendClipPinned write error", "device", ac.DeviceID, "err", err)
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
		if err := ac.Conn.WriteJSON(msg); err != nil {
			slog.Warn("BroadcastWSToUser write failed", "user", userID, "device", ac.DeviceID, "err", err)
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
			if err := ac.Conn.WriteJSON(wsMsg); err != nil {
				slog.Warn("SendToUser write error", "device", ac.DeviceID, "err", err)
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
		return ac.Conn.WriteJSON(wsMsg)
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
