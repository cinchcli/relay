package relay

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"
)

// cliTelemetryAttr is one flat string attribute on a CLI product event. The CLI
// coerces every value (bool, number) to a string before sending, so V is always
// a string here.
type cliTelemetryAttr struct {
	K string `json:"k"`
	V string `json:"v"`
}

// cliTelemetryEvent is a single named CLI product event with its attributes.
type cliTelemetryEvent struct {
	Name  string             `json:"name"`
	Attrs []cliTelemetryAttr `json:"attrs"`
}

// cliTelemetryBatch is the anonymous, opt-in batch a cinch client (CLI or
// desktop) POSTs to /telemetry/otlp. AnonID is a client-generated UUID; it is
// HMAC'd at the relay and never forwarded raw. App names the producing surface
// ("cli" / "desktop") and selects the OTLP service.name (see
// cliTelemetryServiceName); an empty or unknown value defaults to "cinch-cli".
type cliTelemetryBatch struct {
	App    string              `json:"app"`
	AnonID string              `json:"anon_id"`
	Events []cliTelemetryEvent `json:"events"`
}

// cliTelemetryServices maps a client surface to the OTLP service.name its product
// events are recorded under, so CLI and desktop events land in distinct buckets
// the Grafana panels can filter by `service`. Anything not listed (including an
// empty app) falls back to "cinch-cli".
var cliTelemetryServices = map[string]string{
	"cli":     "cinch-cli",
	"desktop": "cinch-desktop",
}

// cliTelemetryServiceName resolves a batch's surface to its service.name, never
// returning an attacker-chosen value: unknown surfaces collapse to "cinch-cli".
func cliTelemetryServiceName(app string) string {
	if s, ok := cliTelemetryServices[app]; ok {
		return s
	}
	return "cinch-cli"
}

// cliTelemetryAllowedEvents is the set of client (CLI + desktop) event names the
// relay forwards. Any other event name is dropped (defense against accidental or
// malicious high-cardinality / PII-bearing event names). Adding a value here is the
// only way to admit a new client event to the observability stack.
var cliTelemetryAllowedEvents = map[string]bool{
	"cli.command.invoked":      true,
	"cli.command.completed":    true,
	"cli.auth.login.started":   true,
	"cli.auth.login.completed": true,
	"cli.send.completed":       true,
	"mcp.session.completed":    true,
	"desktop.app.opened":       true,
}

const (
	// cliTelemetryMaxBytes caps the request body size accepted from the CLI.
	cliTelemetryMaxBytes = 16384
	// cliTelemetryMaxEvents caps how many events one batch may contribute.
	cliTelemetryMaxEvents = 50
	// cliTelemetryMaxAttrs caps non-reserved attributes per event — client
	// properties plus the CLI-injected app/app_version/os/arch dimensions all
	// count against it. The two reserved attrs (event, anon_id) are added on top.
	cliTelemetryMaxAttrs = 16
	// cliTelemetryMaxKeyLen / cliTelemetryMaxValLen bound a single attribute's
	// key/value length to keep cardinality and payload size in check.
	cliTelemetryMaxKeyLen = 64
	cliTelemetryMaxValLen = 256
)

// HandleTelemetryOTLP accepts an anonymous, opt-in batch of cinch-CLI product
// events, anonymizes the caller, and forwards them as OTLP/HTTP logs to the same
// ingest the relay uses for its own product events — distinguished by
// service.name=cinch-cli. It always returns 200 once the payload parses: telemetry
// must never block or surface errors to the client. When the metrics ingest is not
// configured (self-hosters without RELAY_METRICS_* env vars) it silently drops the
// batch. It REUSES the existing metrics primitives (hmacHex, kv, the OTLP structs,
// postOTLPLog) and does NOT touch the relay.* event path in metrics.go.
func (h *Handler) HandleTelemetryOTLP(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength > cliTelemetryMaxBytes {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}

	// Cap the bytes actually read, not just the advertised Content-Length: a chunked
	// request sets ContentLength to -1, sailing past the guard above, and an
	// unbounded json.NewDecoder(r.Body) would then buffer the whole body into memory.
	// io.LimitReader makes the size cap real regardless of how the client framed it.
	var batch cliTelemetryBatch
	if err := json.NewDecoder(io.LimitReader(r.Body, cliTelemetryMaxBytes)).Decode(&batch); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	// Always 200 past this point — telemetry must never block the client.
	w.WriteHeader(http.StatusOK)

	if batch.AnonID == "" || len(batch.Events) == 0 {
		return
	}

	// Silent drop when the ingest is not configured (self-hosters without the
	// RELAY_METRICS_* env vars see no errors). Reuses the same URL/token/salt.
	if !h.metricsConfigured() {
		return
	}

	// Rate-limit by client IP. A heavy dev runs many cinch invocations per hour,
	// so the ceiling is generous; abuse is further bounded by the size caps and
	// the event allowlist.
	if !h.cliTelemetryLimiter.Allow(realIP(r)) {
		return
	}

	records := h.buildCLITelemetryRecords(batch)
	if len(records) == 0 {
		return
	}

	body, err := json.Marshal(otlpLogsBody{
		ResourceLogs: []otlpResourceLogs{{
			Resource:  otlpResource{Attributes: []otlpKeyValue{kv("service.name", cliTelemetryServiceName(batch.App))}},
			ScopeLogs: []otlpScopeLogs{{LogRecords: records}},
		}},
	})
	if err != nil {
		return
	}

	// Fire-and-forget. The recover is belt-and-suspenders for the "telemetry must
	// never affect request handling" contract.
	go func() {
		defer func() { _ = recover() }()
		h.postOTLPLog(body)
	}()
}

// buildCLITelemetryRecords turns an allowlisted, anonymized batch into OTLP log
// records bound to service.name=cinch-cli. The RAW anon_id (client UUID) is HMAC'd
// once here and only the HMAC leaves the process; the raw value never appears in the
// forwarded body. Client attributes are sanitized: reserved keys are rejected, keys
// and values are length-capped, and the per-event attribute count is capped.
func (h *Handler) buildCLITelemetryRecords(batch cliTelemetryBatch) []otlpLogRecord {
	anonOut := hmacHex(h.MetricsAnonSalt, batch.AnonID)

	records := make([]otlpLogRecord, 0, len(batch.Events))
	for _, ev := range batch.Events {
		if len(records) >= cliTelemetryMaxEvents {
			break
		}
		if !cliTelemetryAllowedEvents[ev.Name] {
			continue
		}

		// Reserved attrs first. Clients cannot override these (see below).
		attrs := []otlpKeyValue{
			kv("event", ev.Name),
			kv("anon_id", anonOut),
		}
		clientAttrs := 0
		for _, a := range ev.Attrs {
			if clientAttrs >= cliTelemetryMaxAttrs {
				break
			}
			// Reject empty keys and the reserved keys so a client cannot spoof or
			// override event/anon_id.
			if a.K == "" || a.K == "event" || a.K == "anon_id" {
				continue
			}
			attrs = append(attrs, kv(truncate(a.K, cliTelemetryMaxKeyLen), truncate(a.V, cliTelemetryMaxValLen)))
			clientAttrs++
		}

		records = append(records, otlpLogRecord{
			// Server-receive time; any client-supplied time is ignored.
			TimeUnixNano: strconv.FormatInt(time.Now().UnixNano(), 10),
			Body:         otlpStringValue{StringValue: ev.Name},
			Attributes:   attrs,
		})
	}
	return records
}

// truncate clips s to at most n bytes without splitting a UTF-8 rune: if the byte
// cut would land in the middle of a multi-byte rune, it backs up to the rune
// boundary so the result is always valid UTF-8.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Back up to a UTF-8 leading byte (a continuation byte is 10xxxxxx == 0x80..0xBF).
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}
