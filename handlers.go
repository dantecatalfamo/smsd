package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Notifier is the extension point for pushing inbound messages somewhere
// (Telegram, Matrix, ntfy, email...). Swap logNotifier for a real one. It runs
// in the background, so it may block; it must not modify m.
type Notifier interface {
	Inbound(m Message)
}

type logNotifier struct{}

func (logNotifier) Inbound(m Message) {
	n := 0
	if m.Body != nil {
		n = len([]rune(*m.Body))
	}
	log.Printf("inbound %q from %q to %q: %d chars, %d media", m.SignalWireID, m.Peer, m.Number, n, len(m.Media))
}

type server struct {
	cfg      config
	store    *Store
	sw       *signalWire
	notifier Notifier
	events   *broker
	mediaKey []byte // signs /media-out/ links
	eventKey []byte // signs event stream tickets

	// Background work (notifier calls, media downloads) runs under ctx, which
	// stop cancels. mu makes "check ctx, then wg.Add" atomic with stop, so no
	// Add can race the final Wait.
	mu     sync.Mutex
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func newServer(cfg config, store *Store, sw *signalWire, notifier Notifier) *server {
	ctx, cancel := context.WithCancel(context.Background())
	return &server{cfg: cfg, store: store, sw: sw, notifier: notifier, events: newBroker(),
		mediaKey: deriveKey(cfg.AppToken, "smsd media-out v1"), eventKey: deriveKey(cfg.AppToken, "smsd event ticket v1"),
		ctx: ctx, cancel: cancel}
}

// deriveKey makes a signing key from APP_TOKEN, so what it signs stays valid
// across restarts and rotating the token revokes it.
func deriveKey(appToken, label string) []byte {
	mac := hmac.New(sha256.New, []byte(appToken))
	mac.Write([]byte(label))
	return mac.Sum(nil)
}

// background runs f in a goroutine unless the server is stopping. A panic is
// logged instead of crashing the process.
func (s *server) background(f func(ctx context.Context)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx.Err() != nil {
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() {
			if v := recover(); v != nil {
				log.Printf("background task panicked: %v", v)
			}
		}()
		f(s.ctx)
	}()
}

// stop ends event streams, cancels background work and waits for it to finish.
func (s *server) stop() {
	s.events.close()
	s.mu.Lock()
	s.cancel()
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *server) routes() http.Handler {
	// SignalWire -> us (signature-verified JSON: SWML messaging webhook, status callbacks)
	webhooks := http.NewServeMux()
	webhooks.HandleFunc("POST /webhook/sms", s.handleInbound)
	webhooks.HandleFunc("POST /webhook/status", s.handleStatus)

	// Client -> us (bearer-token auth)
	api := http.NewServeMux()
	api.HandleFunc("GET /api/numbers", s.handleNumbers)
	api.HandleFunc("GET /api/conversations", s.handleConversations)
	api.HandleFunc("GET /api/numbers/{number}/conversations", s.handleConversations)
	api.HandleFunc("GET /api/numbers/{number}/conversations/{peer}", s.handleMessages)
	api.HandleFunc("POST /api/numbers/{number}/conversations/{peer}/messages", s.handleSend)
	api.HandleFunc("GET /api/media/{name}", s.handleMedia)
	// Tickets for the event streams, which are mounted below.
	api.HandleFunc("POST /api/events/ticket", s.handleEventTicket)
	api.HandleFunc("POST /api/numbers/{number}/events/ticket", s.handleEventTicket)
	api.HandleFunc("POST /api/numbers/{number}/conversations/{peer}/events/ticket", s.handleEventTicket)

	// Everything under these prefixes goes through the check, including paths
	// with no route, so unauthenticated callers can't probe which routes exist.
	// The inner muxes match full paths, so no prefix stripping is needed.
	mux := http.NewServeMux()
	mux.Handle("/webhook/", s.verifySignalWire(webhooks))
	mux.Handle("/api/", s.requireToken(api))
	// Event streams take the token or a ticket, for browsers' EventSource,
	// which can't send headers. These patterns are more specific than /api/.
	events := s.eventAuth(http.HandlerFunc(s.handleEvents))
	mux.Handle("GET /api/events", events)
	mux.Handle("GET /api/numbers/{number}/events", events)
	mux.Handle("GET /api/numbers/{number}/conversations/{peer}/events", events)
	// SignalWire -> us, fetching outgoing attachments (signed, expiring links; checked in the handler)
	mux.HandleFunc("GET /media-out/{name}", s.handleMediaOut)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })

	return logRequests(mux)
}

// --- webhooks ---------------------------------------------------------------

func (s *server) verifySignalWire(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The signature covers the raw body, so read it whole before anything parses it.
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
		if err != nil {
			if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
				http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		if !s.cfg.SkipSignature {
			// Must be the exact public URL SignalWire called, not what a proxy rewrote it to.
			fullURL := s.cfg.PublicURL + r.URL.RequestURI()
			if !validSignature(s.cfg.SigningKey, r.Header.Get("X-SignalWire-Signature"), fullURL, raw) {
				log.Printf("rejected webhook: bad signature for %q", fullURL)
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
	// Signed by our project, so any number pointed at this webhook is ours.
	// Anything else is accepted so SignalWire doesn't retry, and not stored.
	if in.Direction != string(Inbound) || !addrPattern.MatchString(in.To) || !addrPattern.MatchString(in.From) {
		log.Printf("ignoring %q: direction %q from %q to %q", in.MessageID, in.Direction, in.From, in.To)
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
		m.Media[i].File, m.Media[i].ServedType = "", "" // ours to set, never SignalWire's
	}

	inserted, err := s.store.Insert(r.Context(), &m)
	if err != nil {
		log.Printf("store inbound: %v", err)
		// Lets SignalWire retry or use the fallback URL; the message_id dedupe makes that safe.
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	if inserted {
		s.events.publish(eventMessage, m)
		s.background(func(context.Context) { s.notifier.Inbound(m) })
		if len(m.Media) > 0 {
			jobs := make([]mediaJob, len(m.Media))
			for i, md := range m.Media {
				jobs[i] = mediaJob{MessageID: m.ID, Position: i, Media: md}
			}
			s.background(func(ctx context.Context) { s.saveMedia(ctx, jobs) })
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
// The whole callback is also stored raw.
type statusPayload struct {
	ID               string          `json:"id"`
	Status           string          `json:"status"`
	ErrorCode        json.RawMessage `json:"error_code"` // provider-specific; not always a string
	ErrorMessage     *string         `json:"error_message"`
	NumberOfSegments *int            `json:"number_of_segments"`
	Timestamp        string          `json:"timestamp"`
}

func (s *server) handleStatus(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body) // already read and bounded by verifySignalWire
	var p statusPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		http.Error(w, "bad JSON", http.StatusBadRequest)
		return
	}
	if p.ID == "" || p.Status == "" {
		log.Printf("status callback without id/status: %q", raw)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	e := StatusEvent{
		SignalWireID: p.ID,
		Status:       p.Status,
		ErrorCode:    errorCode(p.ErrorCode),
		ErrorMessage: p.ErrorMessage,
		Segments:     p.NumberOfSegments,
		At:           parseTime(p.Timestamp, "status timestamp of "+p.ID),
		Raw:          raw,
	}
	if e.ErrorMessage != nil {
		log.Printf("message %q %q: %s %q", p.ID, p.Status, p.ErrorCode, *e.ErrorMessage)
	}
	if err := s.store.AddStatus(r.Context(), e); err != nil {
		log.Printf("store status: %v", err)
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	// A callback that beats its message is applied by Insert and goes out with it.
	s.publishUpdate(s.store.MessageBySignalWireID(r.Context(), p.ID))
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
	want := []byte(s.cfg.AppToken)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme, token, _ := strings.Cut(r.Header.Get("Authorization"), " ")
		if !strings.EqualFold(scheme, "Bearer") || subtle.ConstantTimeCompare([]byte(token), want) != 1 {
			writeJSON(w, http.StatusUnauthorized, errBody("unauthorized"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handleNumbers passes through SignalWire's list of the project's phone numbers.
func (s *server) handleNumbers(w http.ResponseWriter, r *http.Request) {
	nums, err := s.sw.PhoneNumbers(r.Context())
	if err != nil {
		log.Printf("list phone numbers: %v", err)
		if apiErr, ok := errors.AsType[*apiError](err); ok {
			writeJSON(w, http.StatusBadGateway, errBody(apiErr.Message))
			return
		}
		if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
			writeJSON(w, http.StatusGatewayTimeout, errBody("no response from SignalWire"))
			return
		}
		writeJSON(w, http.StatusBadGateway, errBody("listing numbers failed"))
		return
	}
	writeJSON(w, http.StatusOK, nums)
}

// handleConversations lists conversations on one number, or on all of them
// when the route has no {number}.
func (s *server) handleConversations(w http.ResponseWriter, r *http.Request) {
	number := r.PathValue("number")
	if r.Pattern != "GET /api/conversations" && !validAddr(w, number, "number") {
		return
	}
	convs, err := s.store.Conversations(r.Context(), number)
	if err != nil {
		log.Printf("list conversations: %v", err)
		writeJSON(w, http.StatusInternalServerError, errBody("internal error"))
		return
	}
	writeJSON(w, http.StatusOK, convs)
}

func (s *server) handleMessages(w http.ResponseWriter, r *http.Request) {
	number, peer, ok := conversationParams(w, r)
	if !ok {
		return
	}
	limit := 50
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v <= 500 {
		limit = v
	}
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)

	msgs, err := s.store.Messages(r.Context(), number, peer, before, limit)
	if err != nil {
		log.Printf("list messages: %v", err)
		writeJSON(w, http.StatusInternalServerError, errBody("internal error"))
		return
	}
	writeJSON(w, http.StatusOK, msgs)
}

// httpError is a client error with the status to report it with.
type httpError struct {
	status int
	msg    string
}

func (e *httpError) Error() string { return e.msg }

func writeError(w http.ResponseWriter, err error, what string) {
	if he, ok := errors.AsType[*httpError](err); ok {
		writeJSON(w, he.status, errBody(he.msg))
		return
	}
	if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
		writeJSON(w, http.StatusRequestEntityTooLarge, errBody(fmt.Sprintf("request larger than %d bytes", maxUploadBytes)))
		return
	}
	log.Printf("%s: %v", what, err)
	writeJSON(w, http.StatusInternalServerError, errBody("internal error"))
}

const maxBodyBytes = 16 << 10

// parseSend reads a reply: either JSON {"body", "media_files"} or
// multipart/form-data with "body", "media_files" (repeatable) and "media"
// (uploaded files, repeatable) fields. Uploaded files are saved as they're
// read; created lists them so the caller can remove them if the send fails.
func (s *server) parseSend(r *http.Request) (body string, media []outMedia, created []string, err error) {
	addStored := func(name string) error {
		m, err := s.storedMedia(r.Context(), name)
		if err == nil {
			media = append(media, m)
		}
		return err
	}

	if ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); ct != "multipart/form-data" {
		var req struct {
			Body       string   `json:"body"`
			MediaFiles []string `json:"media_files"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return "", nil, nil, &httpError{http.StatusBadRequest, `expected JSON {"body": "...", "media_files": [...]} or multipart/form-data`}
		}
		if len(req.MediaFiles) > maxSendMedia {
			return "", nil, nil, &httpError{http.StatusBadRequest, fmt.Sprintf("at most %d media per message", maxSendMedia)}
		}
		for _, name := range req.MediaFiles {
			if err := addStored(name); err != nil {
				return "", nil, nil, err
			}
		}
		return req.Body, media, nil, nil
	}

	mr, err := r.MultipartReader()
	if err != nil {
		return "", nil, nil, &httpError{http.StatusBadRequest, "bad multipart body"}
	}
	for {
		p, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			return body, media, created, nil
		}
		if err != nil {
			if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
				return "", nil, created, err
			}
			return "", nil, created, &httpError{http.StatusBadRequest, "bad multipart body"}
		}
		tooMany := &httpError{http.StatusBadRequest, fmt.Sprintf("at most %d media per message", maxSendMedia)}
		switch field := p.FormName(); field {
		case "body", "media_files":
			v, err := io.ReadAll(io.LimitReader(p, maxBodyBytes+1))
			if err != nil {
				return "", nil, created, err
			}
			if len(v) > maxBodyBytes {
				return "", nil, created, &httpError{http.StatusBadRequest, field + " too long"}
			}
			if field == "body" {
				body = string(v)
				continue
			}
			if len(media) == maxSendMedia {
				return "", nil, created, tooMany
			}
			if err := addStored(string(v)); err != nil {
				return "", nil, created, err
			}
		case "media":
			if len(media) == maxSendMedia {
				return "", nil, created, tooMany
			}
			m, err := s.saveUpload(p, p.Header.Get("Content-Type"))
			if err != nil {
				return "", nil, created, err
			}
			created = append(created, m.File)
			media = append(media, m)
		default:
			return "", nil, created, &httpError{http.StatusBadRequest, fmt.Sprintf("unknown field %q", field)}
		}
	}
}

func (s *server) handleSend(w http.ResponseWriter, r *http.Request) {
	number, peer, ok := conversationParams(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	body, media, created, err := s.parseSend(r)
	removeCreated := func() {
		for _, f := range created {
			os.Remove(filepath.Join(s.cfg.MediaDir, f))
		}
	}
	if err != nil {
		removeCreated()
		writeError(w, err, "read send request")
		return
	}
	if strings.TrimSpace(body) == "" && len(media) == 0 {
		removeCreated()
		writeJSON(w, http.StatusBadRequest, errBody("a message needs a body or media"))
		return
	}

	now := time.Now()
	stored := make([]Media, len(media))
	urls := make([]string, len(media))
	for i, m := range media {
		urls[i] = s.mediaOutURL(m, now)
		stored[i] = Media{URL: urls[i], ContentType: m.Type, Size: m.Size, File: m.File, ServedType: m.Type}
	}

	// Once SignalWire accepts the message it is sent, so finish sending and
	// recording it even if the client goes away. Send has its own timeout.
	ctx := context.WithoutCancel(r.Context())
	res, err := s.sw.Send(ctx, number, peer, body, urls, s.cfg.PublicURL+"/webhook/status")
	if err != nil {
		log.Printf("send from %q to %q: %v", number, peer, err)
		if apiErr, ok := errors.AsType[*apiError](err); ok {
			removeCreated()
			writeJSON(w, http.StatusBadGateway, errBody(apiErr.Message))
			return
		}
		if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
			// Keep uploads: SignalWire may have the message and still fetch them.
			writeJSON(w, http.StatusGatewayTimeout, errBody("no response from SignalWire; the message may have been sent, check before retrying"))
			return
		}
		removeCreated()
		writeJSON(w, http.StatusBadGateway, errBody("send failed"))
		return
	}

	var bodyPtr *string
	if body != "" {
		bodyPtr = &body
	}
	m := Message{
		SignalWireID: res.ID,
		ProjectID:    res.ProjectID,
		Direction:    Outbound,
		Type:         res.Kind,
		From:         number,
		To:           peer,
		Body:         bodyPtr,
		Segments:     res.NumberOfSegments,
		Media:        stored,
		Status:       res.Status,
		ErrorCode:    errorCode(res.ErrorCode),
		ErrorMessage: res.ErrorMessage,
		Timestamp:    parseTime(res.CreatedAt, "created_at of "+res.ID),
		CreatedAt:    time.Now().UTC(),
		Raw:          res.Raw,
	}
	inserted, err := s.store.Insert(ctx, &m)
	if err != nil || !inserted {
		// The SMS went out; we just failed to record it. Report that honestly.
		log.Printf("store outbound %q: inserted=%v err=%v", res.ID, inserted, err)
		writeJSON(w, http.StatusInternalServerError, errBody("sent but not stored: "+res.ID))
		return
	}
	s.events.publish(eventMessage, m)
	writeJSON(w, http.StatusCreated, m)
}

// --- helpers ----------------------------------------------------------------

// publishUpdate sends a changed message to event streams; it takes a store
// lookup's results directly. A message that isn't stored yet is skipped.
func (s *server) publishUpdate(m Message, err error) {
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		log.Printf("load message for update event: %v", err)
	default:
		s.events.publish(eventUpdate, m)
	}
}

// addrPattern accepts E.164 numbers, short codes and alphanumeric sender IDs,
// for both our numbers and peers. Sends from a number the project doesn't
// own, or to anything SignalWire can't deliver to, come back as its own error.
var addrPattern = regexp.MustCompile(`^\+?[0-9A-Za-z]{2,20}$`)

func validAddr(w http.ResponseWriter, v, what string) bool {
	if !addrPattern.MatchString(v) {
		writeJSON(w, http.StatusBadRequest, errBody(what+" must be a phone number like +16135551234, a short code, or a sender ID"))
		return false
	}
	return true
}

// conversationParams reads {number} (ours) and {peer} from the path.
func conversationParams(w http.ResponseWriter, r *http.Request) (number, peer string, ok bool) {
	number, peer = r.PathValue("number"), r.PathValue("peer")
	ok = validAddr(w, number, "number") && validAddr(w, peer, "peer")
	return number, peer, ok
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

// Unwrap lets http.ResponseController (write deadlines, Flush) reach the real writer.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// ReadFrom keeps the real writer's sendfile path for http.ServeFile.
func (s *statusRecorder) ReadFrom(r io.Reader) (int64, error) { return io.Copy(s.ResponseWriter, r) }

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		// %q: the path is attacker-controlled and could otherwise forge log lines.
		log.Printf("%s %q %d %s", r.Method, r.URL.Path, rec.status, time.Since(start).Round(time.Millisecond))
	})
}
