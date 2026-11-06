package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// sse is one event as a client sees it; comments have kind ":".
type sse struct{ id, kind, data string }

// openStream connects to an event stream on a real HTTP server and returns
// once the server has subscribed it.
func openStream(t *testing.T, s *server, path, lastID string) <-chan sse {
	t.Helper()
	ts := httptest.NewUnstartedServer(s.routes())
	ts.Config.WriteTimeout = 50 * time.Millisecond // streams must outlive it, as they do the real server's
	ts.Start()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(ts.Close) // runs after cancel, so the stream is already gone
	t.Cleanup(cancel)

	req, _ := http.NewRequestWithContext(ctx, "GET", ts.URL+path, nil)
	if !strings.Contains(path, "ticket=") {
		req.Header.Set("Authorization", "Bearer secret")
	}
	if lastID != "" {
		req.Header.Set("Last-Event-ID", lastID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("stream %s: %d %s", path, resp.StatusCode, resp.Header.Get("Content-Type"))
	}

	ch := make(chan sse, 100)
	go func() {
		defer close(ch)
		defer resp.Body.Close()
		var ev sse
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			line := sc.Text()
			field, value, _ := strings.Cut(line, ": ")
			switch {
			case line == "":
				if ev.kind != "" {
					ch <- ev
				}
				ev = sse{}
			case strings.HasPrefix(line, ":"):
				ev.kind, ev.data = ":", strings.TrimPrefix(line, ": ")
			case field == "id":
				ev.id = value
			case field == "event":
				ev.kind = value
			case field == "data":
				ev.data = value
			}
		}
	}()
	if ev := <-ch; ev.kind != ":" || ev.data != "connected" {
		t.Fatalf("first event %+v", ev)
	}
	return ch
}

// nextEvent returns the next non-comment event, failing after a timeout.
func nextEvent(t *testing.T, ch <-chan sse) (sse, Message) {
	t.Helper()
	timeout := time.After(2 * time.Second)
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				t.Fatal("stream ended")
			}
			if ev.kind == ":" {
				continue
			}
			var m Message
			if err := json.Unmarshal([]byte(ev.data), &m); err != nil {
				t.Fatalf("event data %q: %v", ev.data, err)
			}
			return ev, m
		case <-timeout:
			t.Fatal("no event")
		}
	}
}

func expectNoEvent(t *testing.T, ch <-chan sse) {
	t.Helper()
	timeout := time.After(100 * time.Millisecond)
	for {
		select {
		case ev := <-ch:
			if ev.kind != ":" {
				t.Fatalf("unexpected event %+v", ev)
			}
		case <-timeout:
			return
		}
	}
}

func TestEventsScopes(t *testing.T) {
	s := newTestServer(t, "")
	const other, alice = "+16135559999", "+16135551234"
	all := openStream(t, s, "/api/events", "")
	onUs := openStream(t, s, "/api/numbers/%2B16135550000/events", "")
	onOther := openStream(t, s, "/api/numbers/%2B16135559999/events", "")
	withAlice := openStream(t, s, "/api/numbers/%2B16135550000/conversations/%2B16135551234/events", "")
	withBob := openStream(t, s, "/api/numbers/%2B16135550000/conversations/%2B16135554321/events", "")

	signedPost(t, s, "/webhook/sms", inbound("a", alice, us, "to us"))
	signedPost(t, s, "/webhook/sms", inbound("b", alice, other, "to other"))
	signedPost(t, s, "/webhook/sms", inbound("a", alice, us, "to us")) // retry: not a new message

	for _, want := range []string{"a", "b"} {
		if ev, m := nextEvent(t, all); ev.kind != eventMessage || m.SignalWireID != want || ev.id != fmt.Sprint(m.ID) {
			t.Fatalf("all: %+v %+v", ev, m)
		}
	}
	if ev, m := nextEvent(t, onUs); ev.kind != eventMessage || m.SignalWireID != "a" || m.Number != us || *m.Body != "to us" {
		t.Fatalf("on us: %+v %+v", ev, m)
	}
	if _, m := nextEvent(t, onOther); m.SignalWireID != "b" || m.Number != other {
		t.Fatalf("on other: %+v", m)
	}
	if _, m := nextEvent(t, withAlice); m.SignalWireID != "a" || m.Peer != alice {
		t.Fatalf("with alice: %+v", m)
	}
	for _, ch := range []<-chan sse{all, onUs, onOther, withAlice, withBob} {
		expectNoEvent(t, ch)
	}
}

func TestEventsSendAndStatusUpdate(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		w.Write([]byte(`{"id":"out1","status":"queued"}`))
	}))
	defer fake.Close()
	s := newTestServer(t, fake.URL)
	ch := openStream(t, s, "/api/numbers/%2B16135550000/conversations/%2B16135551234/events", "")

	if rec := apiRequest(t, s, "POST", "/api/numbers/%2B16135550000/conversations/%2B16135551234/messages", `{"body":"hi"}`); rec.Code != http.StatusCreated {
		t.Fatalf("send: %d %s", rec.Code, rec.Body)
	}
	ev, m := nextEvent(t, ch)
	if ev.kind != eventMessage || ev.id == "" || m.SignalWireID != "out1" || m.Direction != Outbound || m.Status != "queued" {
		t.Fatalf("sent: %+v %+v", ev, m)
	}

	signedPost(t, s, "/webhook/status", statusCallback("out1", "delivered", "2026-11-05T12:00:01Z", nil, nil))
	ev, m = nextEvent(t, ch)
	if ev.kind != eventUpdate || ev.id != "" || m.SignalWireID != "out1" || m.Status != "delivered" || m.StatusAt == nil {
		t.Fatalf("update: %+v %+v", ev, m)
	}

	// A callback for a message smsd hasn't stored yet has nothing to update.
	signedPost(t, s, "/webhook/status", statusCallback("unknown", "sent", "2026-11-05T12:00:01Z", nil, nil))
	expectNoEvent(t, ch)
}

func TestEventsReplayFromLastEventID(t *testing.T) {
	s := newTestServer(t, "")
	const alice, bob = "+16135551234", "+16135554321"
	signedPost(t, s, "/webhook/sms", inbound("1", alice, us, "one"))
	signedPost(t, s, "/webhook/sms", inbound("2", bob, us, "two"))
	signedPost(t, s, "/webhook/sms", inbound("3", alice, us, "three"))
	first := onlyMessage(t, s, bob).ID - 1 // the id of "1"

	all := openStream(t, s, "/api/events", fmt.Sprint(first))
	withAlice := openStream(t, s, "/api/numbers/%2B16135550000/conversations/%2B16135551234/events", fmt.Sprint(first))
	for _, want := range []string{"2", "3"} {
		if ev, m := nextEvent(t, all); m.SignalWireID != want || ev.id != fmt.Sprint(m.ID) {
			t.Fatalf("all replay: %+v %+v", ev, m)
		}
	}
	if _, m := nextEvent(t, withAlice); m.SignalWireID != "3" {
		t.Fatalf("alice replay: %+v", m)
	}

	// Live events follow the replay, without repeating it.
	signedPost(t, s, "/webhook/sms", inbound("4", alice, us, "four"))
	if _, m := nextEvent(t, all); m.SignalWireID != "4" {
		t.Fatalf("all live: %+v", m)
	}
	if _, m := nextEvent(t, withAlice); m.SignalWireID != "4" {
		t.Fatalf("alice live: %+v", m)
	}
	expectNoEvent(t, all)
}

func TestEventsHeartbeat(t *testing.T) {
	old := heartbeatInterval
	heartbeatInterval = 20 * time.Millisecond
	defer func() { heartbeatInterval = old }()
	s := newTestServer(t, "")
	ch := openStream(t, s, "/api/events", "")
	// Pings keep coming past the test server's 50ms WriteTimeout.
	start := time.Now()
	for time.Since(start) < 150*time.Millisecond {
		select {
		case ev, ok := <-ch:
			if !ok {
				t.Fatalf("stream ended after %v", time.Since(start))
			}
			if ev.kind != ":" || ev.data != "ping" {
				t.Fatalf("got %+v", ev)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("no heartbeat")
		}
	}
}

func TestEventsEndOnShutdown(t *testing.T) {
	s := newTestServer(t, "")
	ch := openStream(t, s, "/api/events", "")
	s.events.close()
	select {
	case _, ok := <-ch:
		for ok {
			_, ok = <-ch
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stream still open after shutdown")
	}
	if rec := apiRequest(t, s, "GET", "/api/events", ""); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("new stream after shutdown: %d", rec.Code)
	}
}

func TestEventsRejectBadRequests(t *testing.T) {
	s := newTestServer(t, "")
	for _, c := range []struct{ path, lastID string }{
		{"/api/numbers/bad%20number/events", ""},
		{"/api/numbers/%2B16135550000/conversations/bad%20peer/events", ""},
		{"/api/events", "nope"},
		{"/api/events", "-1"},
	} {
		req := httptest.NewRequest("GET", c.path, nil)
		req.Header.Set("Authorization", "Bearer secret")
		req.Header.Set("Last-Event-ID", c.lastID)
		rec := httptest.NewRecorder()
		s.routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s (Last-Event-ID %q): got %d", c.path, c.lastID, rec.Code)
		}
	}
	req := httptest.NewRequest("GET", "/api/events", nil) // no token
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: got %d", rec.Code)
	}
}

// A stream that can't keep up is dropped rather than blocking publishers.
func TestBrokerDropsSlowSubscriber(t *testing.T) {
	b := newBroker()
	slow := b.subscribe("", "")
	for i := 0; i <= subscriberBuffer; i++ {
		b.publish(eventMessage, Message{ID: int64(i)})
	}
	n := 0
	for range slow.ch {
		n++
	}
	if n != subscriberBuffer {
		t.Fatalf("got %d buffered events, want %d", n, subscriberBuffer)
	}
	b.unsubscribe(slow) // already dropped: must not close twice
	b.close()
	if b.subscribe("", "") != nil {
		t.Fatal("subscribed after close")
	}
}

func getTicket(t *testing.T, s *server, streamPath string) string {
	t.Helper()
	rec := apiRequest(t, s, "POST", streamPath+"/ticket", "")
	var body struct {
		Ticket    string    `json:"ticket"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != 200 || body.Ticket == "" || time.Until(body.ExpiresAt) <= 0 || time.Until(body.ExpiresAt) > ticketTTL {
		t.Fatalf("ticket for %s: %d %s", streamPath, rec.Code, rec.Body)
	}
	return body.Ticket
}

// get makes an unauthenticated request, as a browser's EventSource would.
func get(s *server, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	return rec
}

func TestTicketOpensItsStream(t *testing.T) {
	s := newTestServer(t, "")
	const conv = "/api/numbers/%2B16135550000/conversations/%2B16135551234/events"
	signedPost(t, s, "/webhook/sms", inbound("1", "+16135551234", us, "one"))
	signedPost(t, s, "/webhook/sms", inbound("2", "+16135551234", us, "two"))
	first := onlyMessageIDs(t, s)[0]

	// A fresh EventSource can't send Last-Event-ID, so it resumes with ?last_event_id=.
	ch := openStream(t, s, conv+"?ticket="+getTicket(t, s, conv)+"&last_event_id="+fmt.Sprint(first), "")
	if _, m := nextEvent(t, ch); m.SignalWireID != "2" {
		t.Fatalf("replay: %+v", m)
	}
	signedPost(t, s, "/webhook/sms", inbound("3", "+16135551234", us, "three"))
	if _, m := nextEvent(t, ch); m.SignalWireID != "3" {
		t.Fatalf("live: %+v", m)
	}

	all := openStream(t, s, "/api/events?ticket="+getTicket(t, s, "/api/events"), "")
	signedPost(t, s, "/webhook/sms", inbound("4", "+16135559876", "+16135559999", "elsewhere"))
	if _, m := nextEvent(t, all); m.SignalWireID != "4" {
		t.Fatalf("all: %+v", m)
	}
}

func onlyMessageIDs(t *testing.T, s *server) []int64 {
	t.Helper()
	msgs, err := s.store.MessagesAfter(t.Context(), "", "", 0, 50)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]int64, len(msgs))
	for i, m := range msgs {
		ids[i] = m.ID
	}
	return ids
}

func TestTicketsRejected(t *testing.T) {
	s := newTestServer(t, "")
	const conv = "/api/numbers/%2B16135550000/conversations/%2B16135551234/events"
	const onUs = "/api/numbers/%2B16135550000/events"
	ticket := getTicket(t, s, conv)
	exp, sig, _ := strings.Cut(ticket, ".")

	past := time.Now().Add(-time.Second).Unix()
	expired := fmt.Sprintf("%d.%s", past, s.ticketMAC(past, "+16135550000", "+16135551234"))
	other := newTestServer(t, "")
	other.eventKey = deriveKey("rotated", "smsd event ticket v1")

	for name, path := range map[string]string{
		"other conversation": "/api/numbers/%2B16135550000/conversations/%2B16135554321/events?ticket=" + ticket,
		"wider scope":        onUs + "?ticket=" + ticket,
		"all messages":       "/api/events?ticket=" + ticket,
		"expired":            conv + "?ticket=" + expired,
		"later expiry":       conv + "?ticket=" + fmt.Sprint(time.Now().Add(time.Hour).Unix()) + "." + sig,
		"bad signature":      conv + "?ticket=" + exp + "." + strings.Repeat("0", len(sig)),
		"no signature":       conv + "?ticket=" + exp,
		"empty":              conv + "?ticket=",
		"not a stream":       "/api/conversations?ticket=" + ticket,
		"not a stream 2":     "/api/numbers/%2B16135550000/conversations/%2B16135551234?ticket=" + ticket,
		"no ticket":          conv,
	} {
		if rec := get(s, path); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: got %d %s", name, rec.Code, rec.Body)
		}
	}
	if rec := get(other, conv+"?ticket="+ticket); rec.Code != http.StatusUnauthorized {
		t.Errorf("after rotating APP_TOKEN: got %d", rec.Code)
	}

	// Minting a ticket needs the token.
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, httptest.NewRequest("POST", conv+"/ticket", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("ticket without token: got %d", rec.Code)
	}
	if rec := apiRequest(t, s, "POST", "/api/numbers/bad%20number/events/ticket", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("ticket for bad number: got %d", rec.Code)
	}
	// A wrong bearer token isn't rescued by a valid ticket.
	req := httptest.NewRequest("GET", conv+"?ticket="+ticket, nil)
	req.Header.Set("Authorization", "Bearer wrong")
	rec = httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token with ticket: got %d", rec.Code)
	}
}
