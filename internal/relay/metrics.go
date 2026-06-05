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
)

// metricsHTTPClient is shared across all emissions to pool idle keep-alive
// connections; its timeout bounds every fire-and-forget POST.
var metricsHTTPClient = &http.Client{Timeout: 5 * time.Second}

// relayUserActiveEvent is the product-event name emitted to the observability
// stack (VictoriaLogs) on each authenticated request. The Grafana "Active users"
// panel runs count_uniq(anon_id) and "Top events" runs stats by(event), both over
// the flat OTLP log-record attributes named exactly "anon_id" and "event".
const relayUserActiveEvent = "relay.user_active"

// activeUserTracker dedups emissions to at most one per anon_id per UTC day, so
// the store sees exactly daily-active users (DAU) instead of one log line per
// request. It self-prunes when the UTC date rolls over.
type activeUserTracker struct {
	mu   sync.Mutex
	day  string
	seen map[string]struct{}
}

func newActiveUserTracker() *activeUserTracker {
	return &activeUserTracker{seen: make(map[string]struct{})}
}

// firstSeenToday reports whether anon was not yet recorded for the given UTC day,
// recording it as a side effect. Concurrency-safe; the critical section is a tiny
// map lookup so it is cheap enough for the auth hot path.
func (t *activeUserTracker) firstSeenToday(anon, day string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if day != t.day {
		t.day = day
		t.seen = make(map[string]struct{})
	}
	if _, ok := t.seen[anon]; ok {
		return false
	}
	t.seen[anon] = struct{}{}
	return true
}

// anonID derives a stable, non-reversible anonymous id from a per-deployment salt
// and the raw user id: hex(HMAC-SHA256(salt, userID)). The account primary key
// never leaves the process, and without the salt the value cannot be reversed to
// a user. A salt rotation intentionally breaks DAU continuity for one window.
func anonID(salt, userID string) string {
	mac := hmac.New(sha256.New, []byte(salt))
	mac.Write([]byte(userID))
	return hex.EncodeToString(mac.Sum(nil))
}

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
	if h.MetricsDisabled || isDemo || userID == "" {
		return
	}
	if h.MetricsIngestURL == "" || h.MetricsIngestToken == "" || h.MetricsAnonSalt == "" {
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
// All errors are swallowed: telemetry must never affect request handling.
func (h *Handler) postUserActiveEvent(anon string) {
	body, err := json.Marshal(otlpLogsBody{
		ResourceLogs: []otlpResourceLogs{{
			Resource: otlpResource{Attributes: []otlpKeyValue{
				// The collector copies service.name -> the "service" field/label.
				{Key: "service.name", Value: otlpStringValue{StringValue: "relay"}},
			}},
			ScopeLogs: []otlpScopeLogs{{
				LogRecords: []otlpLogRecord{{
					TimeUnixNano: strconv.FormatInt(time.Now().UnixNano(), 10),
					Body:         otlpStringValue{StringValue: relayUserActiveEvent},
					// anon_id and event MUST be flat top-level attributes keyed
					// exactly so count_uniq(anon_id) and stats by(event) work.
					Attributes: []otlpKeyValue{
						{Key: "event", Value: otlpStringValue{StringValue: relayUserActiveEvent}},
						{Key: "anon_id", Value: otlpStringValue{StringValue: anon}},
						{Key: "op", Value: otlpStringValue{StringValue: "auth"}},
					},
				}},
			}},
		}},
	})
	if err != nil {
		return
	}

	req, err := http.NewRequest(http.MethodPost, h.MetricsIngestURL+"/v1/logs", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+h.MetricsIngestToken)

	resp, err := metricsHTTPClient.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}
