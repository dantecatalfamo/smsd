package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Notifier is the extension point for pushing inbound messages somewhere
// (Telegram, Matrix, ntfy, email...). Swap logNotifier for a real one.
type Notifier interface {
	Inbound(m Message)
}

type logNotifier struct{}

func (logNotifier) Inbound(m Message) {
	body := ""
	if m.Body != nil {
		body = *m.Body
	}
	log.Printf("inbound from %s: %q (%d media)", m.Peer, body, len(m.Media))
}

type server struct {
	cfg      config
	store    *Store
	sw       *signalWire
	notifier Notifier
	wg       sync.WaitGroup // in-flight media downloads
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()

	// SignalWire -> us (signature-verified JSON: SWML messaging webhook, status callbacks)
	mux.Handle("POST /webhook/sms", s.verifySignalWire(http.HandlerFunc(s.handleInbound)))
	mux.Handle("POST /webhook/status", s.verifySignalWire(http.HandlerFunc(s.handleStatus)))

	// Client -> us (bearer-token auth)
	mux.Handle("GET /api/conversations", s.requireToken(http.HandlerFunc(s.handleConversations)))
	mux.Handle("GET /api/conversations/{peer}", s.requireToken(http.HandlerFunc(s.handleMessages)))
	mux.Handle("POST /api/conversations/{peer}/messages", s.requireToken(http.HandlerFunc(s.handleSend)))
	mux.Handle("GET /api/media/{name}", s.requireToken(http.HandlerFunc(s.handleMedia)))

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })

	return logRequests(mux)
}

// --- webhooks ---------------------------------------------------------------

func (s *server) verifySignalWire(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The signature covers the raw body, so read it whole before anything parses it.
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
		if err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		if !s.cfg.SkipSignature {
			// Must be the exact public URL SignalWire called, not what a proxy rewrote it to.
			fullURL := s.cfg.PublicURL + r.URL.RequestURI()
			if !validSignature(s.cfg.SigningKey, r.Header.Get("X-SignalWire-Signature"), fullURL, raw) {
				log.Printf("rejected webhook: bad signature for %s", fullURL)
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}
		r.Body = io.NopCloser(bytes.NewReader(raw))
		next.ServeHTTP(w, r)
	})
}

// inboundPayload is what SignalWire POSTs to a SWML messaging webhook.
// params and vars are only filled in on transfer/execute fetches, which smsd
// never triggers; they are still kept in the stored raw payload.
type inboundPayload struct {
	Message struct {
		MessageID string  `json:"message_id"`
		ProjectID string  `json:"project_id"`
		SpaceID   string  `json:"space_id"`
		Direction string  `json:"direction"`
		Type      string  `json:"type"`
		From      string  `json:"from"`
		To        string  `json:"to"`
		Body      *string `json:"body"`
		Media     []Media `json:"media"`
		Segments  *int    `json:"segments"`
		Timestamp string  `json:"timestamp"`
	} `json:"message"`
}

func (s *server) handleInbound(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body) // already read and bounded by verifySignalWire
	var p inboundPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		http.Error(w, "bad JSON", http.StatusBadRequest)
		return
	}
	in := p.Message
	if in.MessageID == "" {
		// Without an ID, retries can't be deduplicated.
		http.Error(w, "missing message_id", http.StatusBadRequest)
		return
	}
	if in.Direction != "" && in.Direction != string(Inbound) {
		log.Printf("inbound webhook %s with direction %q", in.MessageID, in.Direction)
	}
	if in.To != s.cfg.FromNumber {
		// Signed by our project, but for another number. Accept so it isn't retried.
		log.Printf("ignoring inbound for %s (we are %s)", in.To, s.cfg.FromNumber)
		writeReceive(w)
		return
	}

	m := Message{
		SignalWireID: in.MessageID,
		ProjectID:    in.ProjectID,
		SpaceID:      in.SpaceID,
		Direction:    Inbound,
		Type:         in.Type,
		From:         in.From,
		To:           in.To,
		Body:         in.Body,
		Segments:     in.Segments,
		Media:        in.Media,
		Status:       "received",
		Timestamp:    parseTime(in.Timestamp, "timestamp of "+in.MessageID),
		CreatedAt:    time.Now().UTC(),
		Raw:          raw,
	}
	for i := range m.Media {
		m.Media[i].File = "" // ours to set, never SignalWire's
	}

	inserted, err := s.store.Insert(r.Context(), &m)
	if err != nil {
		log.Printf("store inbound: %v", err)
		// Lets SignalWire retry or use the fallback URL; the message_id dedupe makes that safe.
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	if inserted {
		s.notifier.Inbound(m)
		if len(m.Media) > 0 {
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				s.saveMedia(ctx, m)
			}()
		}
	}

	writeReceive(w)
}

// receiveSWML accepts an inbound message without replying.
const receiveSWML = `{"version":"1.0.0","sections":{"main":[{"receive":{}}]}}`

func writeReceive(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(receiveSWML))
}

// statusPayload is what SignalWire POSTs to an outbound message's status_callback.
type statusPayload struct {
	ID           string          `json:"id"`
	Status       string          `json:"status"`
	ErrorCode    json.RawMessage `json:"error_code"` // provider-specific; not always a string
	ErrorMessage *string         `json:"error_message"`
	Timestamp    string          `json:"timestamp"`
}

func (s *server) handleStatus(w http.ResponseWriter, r *http.Request) {
	var p statusPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, "bad JSON", http.StatusBadRequest)
		return
	}
	if p.ID == "" || p.Status == "" {
		log.Printf("status callback without id/status: %+v", p)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	u := StatusUpdate{
		SignalWireID: p.ID,
		Status:       p.Status,
		ErrorCode:    errorCode(p.ErrorCode),
		ErrorMessage: p.ErrorMessage,
		At:           parseTime(p.Timestamp, "status timestamp of "+p.ID),
	}
	if u.ErrorMessage != nil {
		log.Printf("message %s %s: %v %s", p.ID, p.Status, string(p.ErrorCode), *u.ErrorMessage)
	}
	if err := s.store.UpdateStatus(r.Context(), u); err != nil {
		log.Printf("update status: %v", err)
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// parseTime parses a SignalWire timestamp; empty or unparseable gives nil
// (logged, rather than silently replaced with our clock).
func parseTime(v, what string) *time.Time {
	if v == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		log.Printf("unparseable %s: %q", what, v)
		return nil
	}
	t = t.UTC()
	return &t
}

// errorCode turns a JSON error_code of any type into text; null gives nil.
func errorCode(raw json.RawMessage) *string {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		s = string(raw)
	}
	return &s
}

// --- API --------------------------------------------------------------------

func (s *server) requireToken(next http.Handler) http.Handler {
	want := []byte("Bearer " + s.cfg.AppToken)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), want) != 1 {
			writeJSON(w, http.StatusUnauthorized, errBody("unauthorized"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *server) handleConversations(w http.ResponseWriter, r *http.Request) {
	convs, err := s.store.Conversations(r.Context())
	if err != nil {
		log.Printf("list conversations: %v", err)
		writeJSON(w, http.StatusInternalServerError, errBody("internal error"))
		return
	}
	writeJSON(w, http.StatusOK, convs)
}

func (s *server) handleMessages(w http.ResponseWriter, r *http.Request) {
	peer, ok := peerParam(w, r)
	if !ok {
		return
	}
	limit := 50
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v <= 500 {
		limit = v
	}
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)

	msgs, err := s.store.Messages(r.Context(), peer, before, limit)
	if err != nil {
		log.Printf("list messages: %v", err)
		writeJSON(w, http.StatusInternalServerError, errBody("internal error"))
		return
	}
	writeJSON(w, http.StatusOK, msgs)
}

func (s *server) handleSend(w http.ResponseWriter, r *http.Request) {
	peer, ok := peerParam(w, r)
	if !ok {
		return
	}
	var req struct {
		Body string `json:"body"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Body) == "" {
		writeJSON(w, http.StatusBadRequest, errBody(`expected JSON {"body": "..."}`))
		return
	}
	if len([]rune(req.Body)) > 1600 {
		writeJSON(w, http.StatusBadRequest, errBody("body exceeds 1600 characters"))
		return
	}

	res, err := s.sw.Send(r.Context(), s.cfg.FromNumber, peer, req.Body, s.cfg.PublicURL+"/webhook/status")
	if err != nil {
		log.Printf("send to %s: %v", peer, err)
		var apiErr *apiError
		if errors.As(err, &apiErr) {
			writeJSON(w, http.StatusBadGateway, errBody(apiErr.Message))
			return
		}
		writeJSON(w, http.StatusBadGateway, errBody("send failed"))
		return
	}

	m := Message{
		SignalWireID: res.ID,
		ProjectID:    res.ProjectID,
		Direction:    Outbound,
		Type:         res.Kind,
		From:         s.cfg.FromNumber,
		To:           peer,
		Body:         &req.Body,
		Segments:     res.NumberOfSegments,
		Status:       res.Status,
		ErrorCode:    errorCode(res.ErrorCode),
		ErrorMessage: res.ErrorMessage,
		Timestamp:    parseTime(res.CreatedAt, "created_at of "+res.ID),
		CreatedAt:    time.Now().UTC(),
		Raw:          res.Raw,
	}
	if _, err := s.store.Insert(r.Context(), &m); err != nil {
		// The SMS went out; we just failed to record it. Report that honestly.
		log.Printf("store outbound %s: %v", res.ID, err)
		writeJSON(w, http.StatusInternalServerError, errBody("sent but not stored: "+res.ID))
		return
	}
	writeJSON(w, http.StatusCreated, m)
}

// --- helpers ----------------------------------------------------------------

var e164 = regexp.MustCompile(`^\+[1-9]\d{6,14}$`)

func peerParam(w http.ResponseWriter, r *http.Request) (string, bool) {
	p := r.PathValue("peer")
	if !e164.MatchString(p) {
		writeJSON(w, http.StatusBadRequest, errBody("peer must be E.164, e.g. +16135551234 (URL-encode + as %2B)"))
		return "", false
	}
	return p, true
}

func errBody(msg string) map[string]string { return map[string]string{"error": msg} }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) { s.status = code; s.ResponseWriter.WriteHeader(code) }

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, rec.status, time.Since(start).Round(time.Millisecond))
	})
}
