package relay

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	cinchv1 "github.com/cinchcli/relay/internal/cinchv1"
)

// metricsHTTPClient is shared across all emissions to pool idle keep-alive
// connections; its timeout bounds every fire-and-forget POST.
var metricsHTTPClient = &http.Client{Timeout: 5 * time.Second}

// Product-event names emitted to the observability stack (VictoriaLogs). The
// Grafana panels key on the flat OTLP log-record attributes exactly:
//   - "Active users":   count_uniq(anon_id) over relay.user_active
//   - "Top events":     stats by(event)
//   - "Loop completion": for each clip_ref, count_uniq(device_ref) >= 2 means a
//     clip sent by one device was read by a DIFFERENT one (a send plus a
//     cross-device read), i.e. the cross-machine clipboard loop completed.
const (
	relayUserActiveEvent = "relay.user_active"
	relayClipSendEvent   = "relay.clip_send"
	relayClipReadEvent   = "relay.clip_read"
)

// dailySeenSet records keys already seen within a UTC day, resetting the set when
// the day rolls over. It backs every daily-deduped product event so the store sees
// one row per key per day instead of one per request: relay.user_active dedups per
// anon_id, clip_send per clip, clip_read per (clip, reader device). The critical
// section is a tiny map lookup, cheap enough for the auth/read hot paths.
type dailySeenSet struct {
	mu   sync.Mutex
	day  string
	seen map[string]struct{}
}

func newDailySeenSet() *dailySeenSet {
	return &dailySeenSet{seen: make(map[string]struct{})}
}

// firstSeenToday reports whether key was not yet recorded for the given UTC day,
// recording it as a side effect. Concurrency-safe.
func (t *dailySeenSet) firstSeenToday(key, day string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if day != t.day {
		t.day = day
		t.seen = make(map[string]struct{})
	}
	if _, ok := t.seen[key]; ok {
		return false
	}
	t.seen[key] = struct{}{}
	return true
}

// hmacHex returns hex(HMAC-SHA256(salt, msg)) — a stable, non-reversible token. It
// anonymizes every identifier that leaves the process under one per-deployment
// salt: user id -> anon_id, clip id -> clip_ref, device id -> device_ref. Without
// the salt none can be reversed to its source; a salt rotation intentionally
// breaks continuity for one window.
func hmacHex(salt, msg string) string {
	mac := hmac.New(sha256.New, []byte(salt))
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}

// anonID derives the anonymous user id (anon_id) for DAU. Thin wrapper over hmacHex
// kept for call-site clarity.
func anonID(salt, userID string) string { return hmacHex(salt, userID) }

// ---- OTLP/HTTP logs payload (typed; the project bans map[string]any) --------

type otlpStringValue struct {
	StringValue string `json:"stringValue"`
}

type otlpKeyValue struct {
	Key   string          `json:"key"`
	Value otlpStringValue `json:"value"`
}

type otlpLogRecord struct {
	TimeUnixNano string          `json:"timeUnixNano"`
	Body         otlpStringValue `json:"body"`
	Attributes   []otlpKeyValue  `json:"attributes"`
}

type otlpScopeLogs struct {
	LogRecords []otlpLogRecord `json:"logRecords"`
}

type otlpResource struct {
	Attributes []otlpKeyValue `json:"attributes"`
}

type otlpResourceLogs struct {
	Resource  otlpResource    `json:"resource"`
	ScopeLogs []otlpScopeLogs `json:"scopeLogs"`
}

type otlpLogsBody struct {
	ResourceLogs []otlpResourceLogs `json:"resourceLogs"`
}

// kv builds a flat OTLP string attribute.
func kv(key, val string) otlpKeyValue {
	return otlpKeyValue{Key: key, Value: otlpStringValue{StringValue: val}}
}

// otlpLog builds a single-record OTLP/HTTP logs body: a service.name=relay resource
// attribute plus the given flat log-record attributes, with the record body set to
// the event name. The collector copies service.name -> the "service" field/label.
func otlpLog(event string, attrs []otlpKeyValue) otlpLogsBody {
	return otlpLogsBody{
		ResourceLogs: []otlpResourceLogs{{
			Resource: otlpResource{Attributes: []otlpKeyValue{kv("service.name", "relay")}},
			ScopeLogs: []otlpScopeLogs{{
				LogRecords: []otlpLogRecord{{
					TimeUnixNano: strconv.FormatInt(time.Now().UnixNano(), 10),
					Body:         otlpStringValue{StringValue: event},
					Attributes:   attrs,
				}},
			}},
		}},
	}
}

// metricsConfigured reports whether the ingest URL, token, and anon salt are all
// set. The salt MUST be present — without it emission is DISABLED rather than ever
// sending a raw identifier.
func (h *Handler) metricsConfigured() bool {
	return h.MetricsIngestURL != "" && h.MetricsIngestToken != "" && h.MetricsAnonSalt != ""
}

// emitUserActive records, fire-and-forget, that the calling user was active. It
// is a no-op (never blocks the request, never panics) unless every precondition
// holds: metrics enabled, ingest URL + token + anon salt all configured, the user
// is not a demo session, and this anon_id has not already been emitted today. The
// salt MUST be set — without it emission is DISABLED rather than ever sending a
// raw user id. Only the HMAC anon_id, the literal service name, the event name,
// and op ever leave the process: never the raw user id, ip, hostname, or clip data.
//
// Called from the two universal authed chokepoints — REST RequireAuth and Connect
// requireConnectAuthHeaders (shared by every Connect interceptor). The legacy
// GET /ws?token= path is not hooked directly, but modern clients mint their WS
// ticket via the authed POST /ws/ticket (which goes through RequireAuth) and any
// working client makes at least one REST/Connect call per UTC day, so daily DAU is
// not undercounted in practice.
func (h *Handler) emitUserActive(userID string, isDemo bool) {
	if h.MetricsDisabled || isDemo || userID == "" || !h.metricsConfigured() {
		return
	}
	anon := anonID(h.MetricsAnonSalt, userID)
	day := time.Now().UTC().Format("20060102")
	if h.activeUsers == nil || !h.activeUsers.firstSeenToday(anon, day) {
		return
	}
	// Fire-and-forget. The recover is belt-and-suspenders for the "telemetry must
	// never affect request handling" contract: postUserActiveEvent is panic-free
	// today, but a future edit to it must never be able to crash the process.
	go func() {
		defer func() { _ = recover() }()
		h.postUserActiveEvent(anon)
	}()
}

// postUserActiveEvent POSTs one OTLP/HTTP log to the ingest front door's /v1/logs.
func (h *Handler) postUserActiveEvent(anon string) {
	// anon_id and event MUST be flat top-level attributes keyed exactly so
	// count_uniq(anon_id) and stats by(event) work.
	body, err := json.Marshal(otlpLog(relayUserActiveEvent, []otlpKeyValue{
		kv("event", relayUserActiveEvent),
		kv("anon_id", anon),
		kv("op", "auth"),
	}))
	if err != nil {
		return
	}
	h.postOTLPLog(body)
}

// emitClipSend records, fire-and-forget, that a clip was sent (pushed) by a device.
// emitClipRead records that a device received/read a clip. Both mirror
// emitUserActive's privacy/fail-safe contract: a no-op unless metrics are enabled,
// the ingest URL + token + salt are all set, the user is not a demo session, and
// the user id and clip id are non-empty. Only HMAC refs leave the process — never
// the raw user id, device id, clip id, source label, hostname, or clip content.
//
// Together the two events let the "Loop completion" panel prove a clip sent on one
// machine was read on another: for a clip_ref, count_uniq(device_ref) >= 2 means
// the sender's device_ref plus at least one different reader's device_ref.
//
// clip_send dedups to one event per clip per UTC day. clip_read dedups to one event
// per (clip, reader device) per UTC day, which collapses the same clip reaching a
// device more than once — a poll loop (re-fetching GET /clips/latest), or a real-
// time delivery followed by a later catch-up pull, or a device reachable on both
// the legacy WS broadcast and the Connect event stream — to a single daily event.
func (h *Handler) emitClipSend(userID, deviceID, clipID string, isDemo bool) {
	h.emitClipEvent(relayClipSendEvent, "send", userID, deviceID, clipID, isDemo, "S:"+clipID)
}

func (h *Handler) emitClipRead(userID, deviceID, clipID string, isDemo bool) {
	h.emitClipEvent(relayClipReadEvent, "read", userID, deviceID, clipID, isDemo, "R:"+clipID+":"+deviceID)
}

// emitClipSendAndDeliveries records, for a freshly pushed (non-duplicate) clip, the
// clip_send plus a clip_read for every device the hub delivered it to over the
// legacy WebSocket broadcast at push time (the push side of loop completion).
// delivered are reader device ids returned by Hub.SendClip; the sender's own device
// may be among them (it is correctly excluded by the dashboard's cross-device test).
// Connect event-stream subscribers are instrumented separately at their delivery
// point (connectEventsServer.Subscribe), and a device reachable on both transports
// is collapsed to one clip_read by the daily (clip, device) dedup.
func (h *Handler) emitClipSendAndDeliveries(userID, senderDeviceID, clipID string, isDemo bool, delivered []string) {
	h.emitClipSend(userID, senderDeviceID, clipID, isDemo)
	for _, dev := range delivered {
		h.emitClipRead(userID, dev, clipID, isDemo)
	}
}

// emitClipReads emits a clip_read for every clip in a list response (history /
// backlog fetch). Per-(clip, reader device) daily dedup keeps a repeated list from
// re-emitting. Nil clips are skipped.
func (h *Handler) emitClipReads(userID, deviceID string, isDemo bool, clips []*cinchv1.Clip) {
	for _, c := range clips {
		if c != nil {
			h.emitClipRead(userID, deviceID, c.ClipId, isDemo)
		}
	}
}

// emitClipEvent is the shared guard, daily dedup, anonymize, and dispatch for clip
// product events. The dedup key is built from the raw ids (in-process only, never
// transmitted); only the HMAC refs are sent.
func (h *Handler) emitClipEvent(event, op, userID, deviceID, clipID string, isDemo bool, dedupKey string) {
	// deviceID is required: an empty device_ref would let count_uniq(device_ref) >= 2
	// falsely register a loop, so a read/send we cannot attribute to a device is
	// dropped rather than emitted with a blank ref. In practice every call site is
	// behind auth, which always sets X-Device-ID from the devices primary key.
	if h.MetricsDisabled || isDemo || userID == "" || clipID == "" || deviceID == "" || !h.metricsConfigured() {
		return
	}
	day := time.Now().UTC().Format("20060102")
	if h.clipEvents == nil || !h.clipEvents.firstSeenToday(dedupKey, day) {
		return
	}
	anon := hmacHex(h.MetricsAnonSalt, userID)
	clipRef := hmacHex(h.MetricsAnonSalt, clipID)
	deviceRef := hmacHex(h.MetricsAnonSalt, deviceID)
	go func() {
		defer func() { _ = recover() }()
		h.postClipEvent(event, op, anon, clipRef, deviceRef)
	}()
}

// postClipEvent POSTs one OTLP/HTTP clip product-event log. Flat attributes the
// Grafana panels key on exactly: event, anon_id, clip_ref, device_ref, op.
func (h *Handler) postClipEvent(event, op, anon, clipRef, deviceRef string) {
	body, err := json.Marshal(otlpLog(event, []otlpKeyValue{
		kv("event", event),
		kv("anon_id", anon),
		kv("clip_ref", clipRef),
		kv("device_ref", deviceRef),
		kv("op", op),
	}))
	if err != nil {
		return
	}
	h.postOTLPLog(body)
}

// postOTLPLog POSTs a pre-marshaled OTLP/HTTP logs body to the ingest front door's
// /v1/logs. All errors are swallowed: telemetry must never affect request handling.
func (h *Handler) postOTLPLog(body []byte) {
	req, err := http.NewRequest(http.MethodPost, h.MetricsIngestURL+"/v1/logs", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+h.MetricsIngestToken)
	// Identify as a named API client. Go's default User-Agent (Go-http-client/1.1)
	// trips Cloudflare's bot-mitigation challenge on the ingest edge (HTTP 403,
	// cf-mitigated: challenge); a non-browser client UA passes it.
	req.Header.Set("User-Agent", h.metricsUserAgent())

	resp, err := metricsHTTPClient.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

// metricsUserAgent identifies the relay to the ingest front door.
func (h *Handler) metricsUserAgent() string {
	if h.Version == "" {
		return "cinch-relay"
	}
	return "cinch-relay/" + h.Version
}
