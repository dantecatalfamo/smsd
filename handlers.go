package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
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

func (logNotifier) Inbound(m Message) { log.Printf("inbound from %s: %q", m.Peer, m.Body) }

type server struct {
	cfg      config
	store    *Store
	sw       *signalWire
	notifier Notifier
	wg       sync.WaitGroup // in-flight media downloads
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()

	// SignalWire -> us (signature-verified)
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
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if !s.cfg.SkipSignature {
			sig := r.Header.Get("X-SignalWire-Signature")
			if sig == "" {
				sig = r.Header.Get("X-Twilio-Signature")
			}
			// Must be the exact public URL SignalWire called, not what a proxy rewrote it to.
			fullURL := s.cfg.PublicURL + r.URL.RequestURI()
			if !validSignature(s.cfg.SigningKey, sig, fullURL, r.PostForm) {
				log.Printf("rejected webhook: bad signature for %s", fullURL)
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *server) handleInbound(w http.ResponseWriter, r *http.Request) {
	f := r.PostForm
	if f.Get("MessageSid") == "" {
		// Without a SID, retries can't be deduplicated.
		http.Error(w, "missing MessageSid", http.StatusBadRequest)
		return
	}
	if to := f.Get("To"); to != s.cfg.FromNumber {
		// Signed by our project, but for another number. Ack so it isn't retried.
		log.Printf("ignoring inbound for %s (we are %s)", to, s.cfg.FromNumber)
		writeEmptyResponse(w)
		return
	}
	m := Message{
		SID:       f.Get("MessageSid"),
		Direction: Inbound,
		Peer:      f.Get("From"),
		Body:      f.Get("Body"),
		Status:    "received",
		CreatedAt: time.Now().UTC(),
	}
	if n, _ := strconv.Atoi(f.Get("NumMedia")); n > 0 {
		for i := 0; i < n && i < 10; i++ {
			if u := f.Get("MediaUrl" + strconv.Itoa(i)); u != "" {
				m.Media = append(m.Media, u)
			}
		}
	}

	inserted, err := s.store.Insert(r.Context(), &m)
	if err != nil {
		log.Printf("store inbound: %v", err)
		// 5xx makes SignalWire retry; the SID dedupe makes that safe.
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

	writeEmptyResponse(w)
}

// writeEmptyResponse acknowledges a webhook with empty cXML (no auto-reply).
func writeEmptyResponse(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/xml")
	w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><Response></Response>`))
}

func (s *server) handleStatus(w http.ResponseWriter, r *http.Request) {
	sid, status := r.PostForm.Get("MessageSid"), r.PostForm.Get("MessageStatus")
	if sid != "" && status != "" {
		if err := s.store.UpdateStatus(r.Context(), sid, status); err != nil {
			log.Printf("update status: %v", err)
			http.Error(w, "store error", http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
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
		SID:       res.SID,
		Direction: Outbound,
		Peer:      peer,
		Body:      req.Body,
		Status:    res.Status,
		CreatedAt: time.Now().UTC(),
	}
	if _, err := s.store.Insert(r.Context(), &m); err != nil {
		// The SMS went out; we just failed to record it. Report that honestly.
		log.Printf("store outbound %s: %v", res.SID, err)
		writeJSON(w, http.StatusInternalServerError, errBody("sent but not stored: "+res.SID))
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
