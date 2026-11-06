package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newTestServer(t *testing.T, swURL string) *server {
	t.Helper()
	dir := t.TempDir()
	st, err := openStore(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg := config{
		PublicURL: "https://sms.example.com", SigningKey: "PSK_test",
		AppToken: "secret", ProjectID: "proj", APIToken: "tok",
		MediaDir: dir, // shared with the DB, so tests show only recorded files are served
	}
	sw := newSignalWire("unused", "proj", "tok")
	if swURL != "" {
		sw.baseURL = swURL
	}
	s := newServer(cfg, st, sw, logNotifier{})
	t.Cleanup(s.stop)
	return s
}

// useTLS points the server's SignalWire client at test TLS servers (they all share one test certificate).
func useTLS(s *server, ts *httptest.Server) { s.sw.http.Transport = ts.Client().Transport }

// signedPost sends a JSON webhook signed the way SignalWire signs them.
func signedPost(t *testing.T, s *server, path string, payload any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", path, strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SignalWire-Signature", hex.EncodeToString(webhookMAC(s.cfg.SigningKey, s.cfg.PublicURL+path, body)))
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	return rec
}

func apiRequest(t *testing.T, s *server, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	return rec
}

type media = map[string]any

func inbound(id, from, to, body string, mediaItems ...media) map[string]any {
	msg := map[string]any{
		"message_id": id, "project_id": "proj", "space_id": "space", "direction": "inbound",
		"type": "sms", "from": from, "to": to, "body": body, "media": []media{}, "segments": 1,
		"timestamp": "2026-11-05T12:00:00Z",
	}
	if len(mediaItems) > 0 {
		msg["type"], msg["media"], msg["body"] = "mms", mediaItems, nil
	}
	return map[string]any{"message": msg, "params": map[string]any{}, "extra": "kept"}
}

func statusCallback(id, status, ts string, errCode any, errMsg any) map[string]any {
	return map[string]any{
		"id": id, "project_id": "proj", "status": status, "to": "+16135551234", "from": "+16135550000",
		"body": "x", "number_of_segments": 2, "timestamp": ts, "error_code": errCode, "error_message": errMsg,
		"custom_variables": map[string]any{"k": "v"},
	}
}

const us = "+16135550000" // our number in most tests

func onlyMessage(t *testing.T, s *server, peer string) Message {
	t.Helper()
	msgs, err := s.store.Messages(t.Context(), us, peer, 0, 50)
	if err != nil || len(msgs) != 1 {
		t.Fatalf("messages for %s: %+v, %v", peer, msgs, err)
	}
	return msgs[0]
}

func storeOutbound(t *testing.T, s *server, id string) {
	t.Helper()
	body := "x"
	m := Message{SignalWireID: id, Direction: Outbound, From: "+16135550000", To: "+16135551234", Body: &body,
		Status: "queued", CreatedAt: time.Now()}
	if ok, err := s.store.Insert(t.Context(), &m); !ok || err != nil {
		t.Fatalf("insert: %v %v", ok, err)
	}
}

// --- inbound ----------------------------------------------------------------

func TestInboundStoresAndDedupes(t *testing.T) {
	s := newTestServer(t, "")
	payload := inbound("m1", "+16135551234", "+16135550000", "hi")

	for i := 0; i < 2; i++ { // second is a retry of the same message_id
		rec := signedPost(t, s, "/webhook/sms", payload)
		if rec.Code != 200 || rec.Body.String() != receiveSWML {
			t.Fatalf("status %d: %s", rec.Code, rec.Body)
		}
	}

	m := onlyMessage(t, s, "+16135551234")
	if m.SignalWireID != "m1" || m.ProjectID != "proj" || m.SpaceID != "space" || m.Direction != Inbound ||
		m.Type != "sms" || m.From != "+16135551234" || m.To != "+16135550000" || m.Number != us || m.Peer != "+16135551234" ||
		m.Body == nil || *m.Body != "hi" || m.Segments == nil || *m.Segments != 1 || m.Status != "received" {
		t.Fatalf("got %+v", m)
	}
	if want := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC); m.Timestamp == nil || !m.Timestamp.Equal(want) {
		t.Fatalf("timestamp %v, want %v", m.Timestamp, want)
	}
	// The raw payload keeps everything, including params and fields we don't model.
	var raw map[string]any
	if err := json.Unmarshal(m.Raw, &raw); err != nil || raw["params"] == nil || raw["extra"] != "kept" {
		t.Fatalf("raw: %s %v", m.Raw, err)
	}
}

func TestInboundRejectsBadSignature(t *testing.T) {
	s := newTestServer(t, "")
	for _, sig := range []string{"bogus", "", "00"} {
		req := httptest.NewRequest("POST", "/webhook/sms", strings.NewReader(`{"message":{"message_id":"m1"}}`))
		req.Header.Set("X-SignalWire-Signature", sig)
		rec := httptest.NewRecorder()
		s.routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("sig %q: want 403, got %d", sig, rec.Code)
		}
	}
}

func TestSignatureCoversQueryString(t *testing.T) {
	s := newTestServer(t, "")
	body := []byte(`{"message":{}}`)
	path := "/webhook/sms?a=b%20c&x=1"
	req := httptest.NewRequest("POST", path, strings.NewReader(string(body)))
	req.Header.Set("X-SignalWire-Signature", hex.EncodeToString(webhookMAC("PSK_test", "https://sms.example.com"+path, body)))
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest { // past the signature check, then rejected for missing message_id
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
}

func TestSkipSignature(t *testing.T) {
	s := newTestServer(t, "")
	s.cfg.SkipSignature = true
	body, _ := json.Marshal(inbound("m1", "+16135551234", "+16135550000", "hi"))
	req := httptest.NewRequest("POST", "/webhook/sms", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestWebhookBodyTooLarge(t *testing.T) {
	s := newTestServer(t, "")
	req := httptest.NewRequest("POST", "/webhook/sms", strings.NewReader(strings.Repeat("x", 64<<10+1)))
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestSignatureEncoding(t *testing.T) {
	body := []byte(`{"message":{}}`)
	u := "https://sms.example.com/webhook/sms"
	sig := hex.EncodeToString(webhookMAC("PSK_test", u, body))
	if !validSignature("PSK_test", sig, u, body) || !validSignature("PSK_test", strings.ToUpper(sig), u, body) {
		t.Fatal("rejected a valid signature")
	}
	for _, bad := range []string{"", sig[:len(sig)-1], "zz" + sig[2:]} {
		if validSignature("PSK_test", bad, u, body) {
			t.Fatalf("accepted %q", bad)
		}
	}
	if validSignature("PSK_test", sig, u, []byte(`{"message":{"x":1}}`)) {
		t.Fatal("accepted signature for a different body")
	}
}

func TestInboundIgnoresOtherDirectionsAndBadNumbers(t *testing.T) {
	s := newTestServer(t, "")
	outbound := inbound("m5", "+16135551234", us, "hi")
	outbound["message"].(map[string]any)["direction"] = "outbound"
	for _, p := range []map[string]any{outbound, inbound("m6", "+16135551234", "", "hi"), inbound("m7", "", us, "hi")} {
		if rec := signedPost(t, s, "/webhook/sms", p); rec.Code != 200 || rec.Body.String() != receiveSWML {
			t.Fatalf("status %d", rec.Code)
		}
	}
	if convs, _ := s.store.Conversations(t.Context(), ""); len(convs) != 0 {
		t.Fatalf("stored: %+v", convs)
	}
}

// One peer texting two of our numbers gets a conversation on each, and
// replies go out from the number in the path.
func TestMultipleNumbers(t *testing.T) {
	var froms []string
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct{ From string }
		json.NewDecoder(r.Body).Decode(&req)
		froms = append(froms, req.From)
		w.WriteHeader(201)
		fmt.Fprintf(w, `{"id":"out%d","status":"queued"}`, len(froms))
	}))
	defer fake.Close()
	s := newTestServer(t, fake.URL)
	const other = "+16135559999"
	signedPost(t, s, "/webhook/sms", inbound("a", "+16135551234", us, "to first"))
	signedPost(t, s, "/webhook/sms", inbound("b", "+16135551234", other, "to second"))

	if rec := apiRequest(t, s, "POST", "/api/numbers/%2B16135559999/conversations/%2B16135551234/messages", `{"body":"from second"}`); rec.Code != http.StatusCreated {
		t.Fatalf("send: %d %s", rec.Code, rec.Body)
	}
	if len(froms) != 1 || froms[0] != other {
		t.Fatalf("sent from %v", froms)
	}

	var all []Conversation
	json.Unmarshal(apiRequest(t, s, "GET", "/api/conversations", "").Body.Bytes(), &all)
	if len(all) != 2 || all[0].Number != other || all[0].MessageCount != 2 || all[1].Number != us || all[1].MessageCount != 1 {
		t.Fatalf("all conversations: %+v", all)
	}
	var mine []Conversation
	json.Unmarshal(apiRequest(t, s, "GET", "/api/numbers/%2B16135550000/conversations", "").Body.Bytes(), &mine)
	if len(mine) != 1 || mine[0].Number != us || *mine[0].LastBody != "to first" {
		t.Fatalf("conversations on %s: %+v", us, mine)
	}

	var msgs []Message
	json.Unmarshal(apiRequest(t, s, "GET", "/api/numbers/%2B16135559999/conversations/%2B16135551234", "").Body.Bytes(), &msgs)
	if len(msgs) != 2 || *msgs[0].Body != "to second" || *msgs[1].Body != "from second" ||
		msgs[1].From != other || msgs[1].Number != other || msgs[1].Peer != "+16135551234" {
		t.Fatalf("messages on %s: %+v", other, msgs)
	}
	if rec := apiRequest(t, s, "GET", "/api/numbers/bad%20number/conversations", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad number: got %d", rec.Code)
	}
}

func TestInboundRequiresMessageID(t *testing.T) {
	s := newTestServer(t, "")
	if rec := signedPost(t, s, "/webhook/sms", inbound("", "+16135551234", "+16135550000", "hi")); rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

// --- sending and statuses ---------------------------------------------------

func TestSendListAndStatus(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, _ := r.BasicAuth()
		var req struct{ From, To, Body, Status_Callback string }
		json.NewDecoder(r.Body).Decode(&req)
		if r.URL.Path != "/messages" || u != "proj" || p != "tok" || req.To != "+16135551234" || req.From != "+16135550000" ||
			req.Body != "hello back" || req.Status_Callback != "https://sms.example.com/webhook/status" {
			http.Error(w, `{"errors":[{"detail":"bad request"}]}`, 422)
			return
		}
		w.WriteHeader(201)
		w.Write([]byte(`{"id":"m2","project_id":"proj","status":"queued","kind":"sms","number_of_segments":1,
			"error_code":null,"error_message":null,"created_at":"2026-11-05T12:00:00Z"}`))
	}))
	defer fake.Close()
	s := newTestServer(t, fake.URL)

	// A literal + in the path works as well as %2B.
	if rec := apiRequest(t, s, "POST", "/api/numbers/+16135550000/conversations/+16135551234/messages", `{"body":"hello back"}`); rec.Code != http.StatusCreated {
		t.Fatalf("send: %d %s", rec.Code, rec.Body)
	}

	rec := apiRequest(t, s, "GET", "/api/conversations", "")
	var convs []Conversation
	json.Unmarshal(rec.Body.Bytes(), &convs)
	if len(convs) != 1 || convs[0].Number != us || convs[0].Peer != "+16135551234" || convs[0].LastDirection != Outbound {
		t.Fatalf("conversations: %s", rec.Body)
	}

	if rec := signedPost(t, s, "/webhook/status", statusCallback("m2", "undelivered", "2026-11-05T12:00:01Z", 30007, "Carrier filtered")); rec.Code != http.StatusNoContent {
		t.Fatalf("status callback: %d %s", rec.Code, rec.Body)
	}
	m := onlyMessage(t, s, "+16135551234")
	if m.Status != "undelivered" || m.ErrorCode == nil || *m.ErrorCode != "30007" || m.ErrorMessage == nil ||
		m.StatusAt == nil || !m.StatusAt.Equal(time.Date(2026, 11, 5, 12, 0, 1, 0, time.UTC)) ||
		m.Segments == nil || *m.Segments != 2 || m.Type != "sms" || m.From != "+16135550000" ||
		!strings.Contains(string(m.Raw), `"kind":"sms"`) {
		t.Fatalf("after status callback: %+v", m)
	}
	// The whole callback is kept.
	var raw string
	s.store.db.QueryRow(`SELECT raw FROM status_events WHERE signalwire_id = 'm2'`).Scan(&raw)
	if !strings.Contains(raw, `"custom_variables"`) {
		t.Fatalf("status raw: %q", raw)
	}

	req := httptest.NewRequest("GET", "/api/conversations", nil) // no token
	rec = httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
}

func TestLateStatusDoesNotOverwriteNewer(t *testing.T) {
	s := newTestServer(t, "")
	storeOutbound(t, s, "m1")
	for _, cb := range []map[string]any{
		statusCallback("m1", "undelivered", "2026-11-05T12:00:05Z", 30007, "Carrier filtered"),
		statusCallback("m1", "sent", "2026-11-05T12:00:01Z", nil, nil), // late
		statusCallback("m1", "queued", "", nil, nil),                   // no timestamp ranks last
	} {
		if rec := signedPost(t, s, "/webhook/status", cb); rec.Code != http.StatusNoContent {
			t.Fatalf("callback: %d", rec.Code)
		}
	}
	m := onlyMessage(t, s, "+16135551234")
	if m.Status != "undelivered" || m.ErrorCode == nil || *m.ErrorCode != "30007" {
		t.Fatalf("got %+v", m)
	}
}

// Two final statuses: only the timestamps say which is current.
func TestNewerFinalStatusWins(t *testing.T) {
	s := newTestServer(t, "")
	storeOutbound(t, s, "m1")
	signedPost(t, s, "/webhook/status", statusCallback("m1", "failed", "2026-11-05T12:00:05Z", nil, nil))
	signedPost(t, s, "/webhook/status", statusCallback("m1", "delivered", "2026-11-05T12:00:01Z", nil, nil)) // arrives later
	if m := onlyMessage(t, s, "+16135551234"); m.Status != "failed" {
		t.Fatalf("got %q", m.Status)
	}
}

func TestEqualTimestampsUseStatusOrder(t *testing.T) {
	s := newTestServer(t, "")
	storeOutbound(t, s, "m1")
	signedPost(t, s, "/webhook/status", statusCallback("m1", "delivered", "2026-11-05T12:00:01Z", nil, nil))
	signedPost(t, s, "/webhook/status", statusCallback("m1", "sent", "2026-11-05T12:00:01Z", nil, nil))
	if m := onlyMessage(t, s, "+16135551234"); m.Status != "delivered" {
		t.Fatalf("got %q", m.Status)
	}
}

// The status callback can arrive before handleSend has stored the message.
func TestStatusBeforeInsertIsApplied(t *testing.T) {
	s := newTestServer(t, "")
	signedPost(t, s, "/webhook/status", statusCallback("m3", "delivered", "2026-11-05T12:00:02Z", nil, nil))
	signedPost(t, s, "/webhook/status", statusCallback("m3", "sent", "2026-11-05T12:00:01Z", nil, nil))

	body := "x"
	m := Message{SignalWireID: "m3", Direction: Outbound, From: "+16135550000", To: "+16135551234", Body: &body,
		Status: "queued", CreatedAt: time.Now()}
	if _, err := s.store.Insert(t.Context(), &m); err != nil {
		t.Fatal(err)
	}
	if m.Status != "delivered" || m.StatusAt == nil || m.Segments == nil || *m.Segments != 2 || m.Peer != "+16135551234" {
		t.Fatalf("returned %+v", m)
	}
	if got := onlyMessage(t, s, "+16135551234"); got.Status != "delivered" {
		t.Fatalf("stored %q", got.Status)
	}
}

func TestSendReportsAPIError(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":[{"code":"invalid","message":"Invalid","detail":"to is not a valid number"}]}`, 422)
	}))
	defer fake.Close()
	s := newTestServer(t, fake.URL)
	rec := apiRequest(t, s, "POST", "/api/numbers/%2B16135550000/conversations/%2B16135551234/messages", `{"body":"x"}`)
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "to is not a valid number") {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
}

// A client that gives up mid-send must not lose the record of a message SignalWire accepted.
func TestSendSurvivesClientDisconnect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cancel() // the client disconnects while SignalWire is answering
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(201)
		w.Write([]byte(`{"id":"m9","status":"queued"}`))
	}))
	defer fake.Close()
	s := newTestServer(t, fake.URL)

	req := httptest.NewRequestWithContext(ctx, "POST", "/api/numbers/%2B16135550000/conversations/%2B16135551234/messages", strings.NewReader(`{"body":"x"}`))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if m := onlyMessage(t, s, "+16135551234"); m.SignalWireID != "m9" {
		t.Fatalf("got %+v", m)
	}
}

func TestSendTimeoutIsReportedAsUnknown(t *testing.T) {
	release := make(chan struct{})
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	defer fake.Close()
	defer close(release)
	old := sendTimeout
	sendTimeout = 50 * time.Millisecond
	defer func() { sendTimeout = old }()

	s := newTestServer(t, fake.URL)
	rec := apiRequest(t, s, "POST", "/api/numbers/%2B16135550000/conversations/%2B16135551234/messages", `{"body":"x"}`)
	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
}

func TestShortCodeConversationsAreReachable(t *testing.T) {
	s := newTestServer(t, "")
	signedPost(t, s, "/webhook/sms", inbound("m1", "12345", "+16135550000", "Your code is 1234"))
	rec := apiRequest(t, s, "GET", "/api/numbers/%2B16135550000/conversations/12345", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Your code is 1234") {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	if rec := apiRequest(t, s, "GET", "/api/numbers/%2B16135550000/conversations/bad%20peer", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad peer: got %d", rec.Code)
	}
}

// --- media ------------------------------------------------------------------

func TestInboundMediaSavedAndServed(t *testing.T) {
	var gotAuth atomic.Value
	mediaSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth.Store(r.Header.Get("Authorization"))
		switch r.URL.Path {
		case "/html":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte("<script>alert(1)</script>"))
		case "/missing":
			http.NotFound(w, r)
		case "/huge":
			w.Write(make([]byte, maxMediaBytes+1)) // declared small, actually too big
		default:
			w.Header().Set("Content-Type", "image/jpeg")
			w.Write([]byte("fakejpeg"))
		}
	}))
	defer mediaSrv.Close()
	s := newTestServer(t, "")
	useTLS(s, mediaSrv)
	s.sw.space = mediaSrv.Listener.Addr().String() // media is on our own space: credentials allowed

	// More attachments than the old 10 cap, plus problem cases.
	var items []media
	for i := 0; i < 12; i++ {
		items = append(items, media{"url": mediaSrv.URL + "/jpg", "content_type": "image/jpeg", "size": 8})
	}
	items[1]["size"] = maxMediaBytes + 1                                         // declared too large: skipped
	items[2]["file"] = "../../etc/passwd"                                        // can't set our fields
	items[3]["url"] = mediaSrv.URL + "/html"                                     // active content
	items[4]["url"] = mediaSrv.URL + "/missing"                                  // download fails
	items[5]["url"] = mediaSrv.URL + "/huge"                                     // too big once streamed
	items[6]["url"] = strings.Replace(mediaSrv.URL, "https", "http", 1) + "/jpg" // plain http refused
	payload := inbound("SM5", "+16135551234", "+16135550000", "", items...)
	if rec := signedPost(t, s, "/webhook/sms", payload); rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	s.wg.Wait()

	if a, _ := gotAuth.Load().(string); !strings.HasPrefix(a, "Basic ") {
		t.Fatalf("own-space media fetched without credentials: %q", a)
	}
	m := onlyMessage(t, s, "+16135551234")
	if len(m.Media) != 12 || m.Body != nil || m.Type != "mms" {
		t.Fatalf("got %+v", m)
	}
	for i, md := range m.Media {
		want, wantType := fmt.Sprintf("%d-%d.jpg", m.ID, i), "image/jpeg"
		switch i {
		case 1, 4, 5, 6:
			want, wantType = "", ""
		case 3:
			want, wantType = fmt.Sprintf("%d-3", m.ID), "text/html"
		}
		if md.File != want || md.ServedType != wantType {
			t.Fatalf("media[%d] = %+v, want file %q type %q", i, md, want, wantType)
		}
	}
	if tmp, _ := filepath.Glob(filepath.Join(s.cfg.MediaDir, tempMediaPrefix+"*")); len(tmp) != 0 {
		t.Fatalf("temp files left: %v", tmp)
	}

	rec := apiRequest(t, s, "GET", "/api/media/"+m.Media[0].File, "")
	if rec.Code != 200 || rec.Body.String() != "fakejpeg" || rec.Header().Get("Content-Type") != "image/jpeg" ||
		rec.Header().Get("Content-Disposition") != "" || rec.Header().Get("Content-Security-Policy") != "sandbox" {
		t.Fatalf("serve jpg: %d %q %v", rec.Code, rec.Body, rec.Header())
	}
	rec = apiRequest(t, s, "GET", "/api/media/"+m.Media[3].File, "")
	if rec.Code != 200 || rec.Header().Get("Content-Disposition") != "attachment" ||
		rec.Header().Get("Content-Type") != "text/html" || rec.Header().Get("Content-Security-Policy") != "sandbox" {
		t.Fatalf("serve html: %d %v", rec.Code, rec.Header())
	}
	// Only files smsd recorded are served, even though the DB sits in MEDIA_DIR here.
	for _, name := range []string{"test.db", "..%2Ftest.db", "nope.jpg"} {
		if rec := apiRequest(t, s, "GET", "/api/media/"+name, ""); rec.Code != http.StatusNotFound {
			t.Fatalf("%s: want 404, got %d", name, rec.Code)
		}
	}
}

func TestMediaCredentialsOnlyToOwnSpace(t *testing.T) {
	var gotAuth atomic.Value
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth.Store(r.Header.Get("Authorization"))
		w.Write([]byte("x"))
	}))
	defer other.Close()
	space := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/x", http.StatusFound) // same host, different port
	}))
	defer space.Close()

	s := newTestServer(t, "")
	useTLS(s, space)
	s.sw.space = space.Listener.Addr().String()
	for _, u := range []string{space.URL + "/m", other.URL + "/m"} {
		gotAuth.Store("unset")
		resp, err := s.sw.Fetch(t.Context(), u)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if a := gotAuth.Load().(string); a != "" {
			t.Fatalf("%s: credentials reached another host: %q", u, a)
		}
	}
}

func TestMissingMediaRetried(t *testing.T) {
	var up atomic.Bool
	mediaSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			http.Error(w, "down", 503)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Write([]byte("png"))
	}))
	defer mediaSrv.Close()
	s := newTestServer(t, "")
	useTLS(s, mediaSrv)
	signedPost(t, s, "/webhook/sms", inbound("m1", "+16135551234", "+16135550000", "",
		media{"url": mediaSrv.URL + "/a", "content_type": "image/png", "size": 3}))
	s.wg.Wait()

	up.Store(true)
	jobs, err := s.store.MissingMedia(t.Context(), time.Now().Add(-time.Hour))
	if err != nil || len(jobs) != 1 {
		t.Fatalf("missing: %+v %v", jobs, err)
	}
	s.saveMedia(t.Context(), jobs)
	if m := onlyMessage(t, s, "+16135551234"); m.Media[0].File == "" || m.Media[0].ServedType != "image/png" {
		t.Fatalf("after retry: %+v", m.Media)
	}
	if jobs, _ := s.store.MissingMedia(t.Context(), time.Now().Add(-time.Hour)); len(jobs) != 0 {
		t.Fatalf("still missing: %+v", jobs)
	}
}

func TestCleanMediaDir(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, tempMediaPrefix+"123"), nil, 0o600)
	os.WriteFile(filepath.Join(dir, "1-0.jpg"), nil, 0o600)
	if err := cleanMediaDir(dir); err != nil {
		t.Fatal(err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*")); len(left) != 1 || filepath.Base(left[0]) != "1-0.jpg" {
		t.Fatalf("left: %v", left)
	}
}

func TestServedInline(t *testing.T) {
	for ct, want := range map[string]bool{
		"image/jpeg": true, "video/mp4": true, "audio/amr": true, "image/svg+xml": false,
		"text/html": false, "text/plain; charset=utf-8": false, "application/octet-stream": false, "": false,
	} {
		if got := servedInline(ct); got != want {
			t.Errorf("%q: got %v", ct, got)
		}
	}
}

// --- server lifecycle, routing, auth, config --------------------------------

func TestBackgroundAfterStopDoesNotRun(t *testing.T) {
	s := newTestServer(t, "")
	s.stop()
	ran := false
	s.background(func(context.Context) { ran = true })
	s.wg.Wait()
	if ran {
		t.Fatal("background task ran after stop")
	}
}

func TestBackgroundPanicIsContained(t *testing.T) {
	s := newTestServer(t, "")
	s.background(func(context.Context) { panic("boom") })
	s.wg.Wait()
}

// The auth checks wrap whole prefixes, not individual routes.
func TestPrefixesAreProtected(t *testing.T) {
	s := newTestServer(t, "")
	h := s.routes()
	cases := []struct {
		method, path, auth string
		want               int
	}{
		{"GET", "/api/nope", "", http.StatusUnauthorized},
		{"GET", "/api/nope", "Bearer secret", http.StatusNotFound},
		{"GET", "/api/nope", "bearer secret", http.StatusNotFound}, // scheme is case-insensitive
		{"GET", "/api/nope", "Bearer wrong", http.StatusUnauthorized},
		{"GET", "/api/nope", "Basic secret", http.StatusUnauthorized},
		{"DELETE", "/api/conversations", "", http.StatusUnauthorized},
		{"DELETE", "/api/conversations", "Bearer secret", http.StatusMethodNotAllowed},
		{"GET", "/api/numbers/%2B16135550000/conversations/%2B16135551234", "Bearer secret", http.StatusOK}, // path values survive nesting
		{"POST", "/webhook/nope", "", http.StatusForbidden},
		{"GET", "/healthz", "", http.StatusOK},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, c.path, nil)
		if c.auth != "" {
			req.Header.Set("Authorization", c.auth)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("%s %s (auth %q): got %d, want %d", c.method, c.path, c.auth, rec.Code, c.want)
		}
	}
}

func TestLogRequestsQuotesPath(t *testing.T) {
	var buf strings.Builder
	out := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(out)
	logRequests(http.NotFoundHandler()).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/x%0Aforged", nil))
	if strings.Count(buf.String(), "\n") != 1 {
		t.Fatalf("log line split: %q", buf.String())
	}
}

func TestLoadConfig(t *testing.T) {
	base := map[string]string{
		"PUBLIC_URL": "https://sms.example.com/", "SW_SPACE": "x.signalwire.com", "SW_PROJECT_ID": "p",
		"SW_API_TOKEN": "t", "SW_SIGNING_KEY": "k", "APP_TOKEN": "a",
	}
	load := func(over map[string]string) (config, error) {
		return loadConfig(func(k string) string {
			if v, ok := over[k]; ok {
				return v
			}
			return base[k]
		})
	}
	c, err := load(nil)
	if err != nil || c.PublicURL != "https://sms.example.com" || c.Addr != ":8080" {
		t.Fatalf("valid config: %+v %v", c, err)
	}
	for name, over := range map[string]map[string]string{
		"missing":          {"APP_TOKEN": "", "SW_SPACE": ""},
		"url no scheme":    {"PUBLIC_URL": "sms.example.com"},
		"url query":        {"PUBLIC_URL": "https://sms.example.com/?a=1"},
		"url creds":        {"PUBLIC_URL": "https://u:p@sms.example.com"},
		"space with url":   {"SW_SPACE": "https://x.signalwire.com"},
		"skip sig exposed": {"SKIP_SIGNATURE": "1", "ADDR": ":8080"},
	} {
		if _, err := load(over); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := load(map[string]string{"APP_TOKEN": "", "SW_SPACE": ""}); err == nil ||
		!strings.Contains(err.Error(), "APP_TOKEN, SW_SPACE") {
		t.Errorf("missing vars not all reported: %v", err)
	}
	for _, addr := range []string{"127.0.0.1:8080", "[::1]:8080", "localhost:8080"} {
		if _, err := load(map[string]string{"SKIP_SIGNATURE": "1", "SW_SIGNING_KEY": "", "ADDR": addr}); err != nil {
			t.Errorf("skip sig on %s: %v", addr, err)
		}
	}
}

func TestMigrations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	for i := 0; i < 2; i++ { // second open must find nothing to do
		st, err := openStore(path)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		var v int
		st.db.QueryRow(`PRAGMA user_version`).Scan(&v)
		if v != len(migrations) {
			t.Fatalf("open %d: user_version %d, want %d", i, v, len(migrations))
		}
		if i == 1 {
			st.db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, len(migrations)+1))
		}
		st.Close()
	}
	if st, err := openStore(path); err == nil {
		st.Close()
		t.Fatal("opened a database from a newer version")
	}
}

// --- outbound media ---------------------------------------------------------

type sentRequest struct {
	Body  *string  `json:"body"`
	Media []string `json:"media"`
}

// fakeSignalWire accepts sends and records the last one; status != 201 fails them.
func fakeSignalWire(t *testing.T, status int) (*httptest.Server, *atomic.Pointer[sentRequest]) {
	t.Helper()
	var last atomic.Pointer[sentRequest]
	var n atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req sentRequest
		json.NewDecoder(r.Body).Decode(&req)
		last.Store(&req)
		if status != 201 {
			http.Error(w, `{"errors":[{"detail":"rejected"}]}`, status)
			return
		}
		w.WriteHeader(201)
		fmt.Fprintf(w, `{"id":"out%d","status":"queued","kind":"mms"}`, n.Add(1))
	}))
	t.Cleanup(ts.Close)
	return ts, &last
}

type part struct{ field, filename, contentType, content string }

func multipartSend(t *testing.T, s *server, parts ...part) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, p := range parts {
		h := textproto.MIMEHeader{}
		disp := fmt.Sprintf(`form-data; name=%q`, p.field)
		if p.filename != "" {
			disp += fmt.Sprintf(`; filename=%q`, p.filename)
		}
		h.Set("Content-Disposition", disp)
		if p.contentType != "" {
			h.Set("Content-Type", p.contentType)
		}
		w, _ := mw.CreatePart(h)
		w.Write([]byte(p.content))
	}
	mw.Close()
	req := httptest.NewRequest("POST", "/api/numbers/%2B16135550000/conversations/%2B16135551234/messages", &buf)
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	return rec
}

// fetchAsSignalWire GETs a /media-out/ link the way SignalWire would: no credentials.
func fetchAsSignalWire(t *testing.T, s *server, link string) *httptest.ResponseRecorder {
	t.Helper()
	path := strings.TrimPrefix(link, s.cfg.PublicURL)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	return rec
}

func outFiles(t *testing.T, s *server) []string {
	t.Helper()
	f, _ := filepath.Glob(filepath.Join(s.cfg.MediaDir, "out-*"))
	return f
}

func TestSendWithUploadedMedia(t *testing.T) {
	fake, last := fakeSignalWire(t, 201)
	s := newTestServer(t, fake.URL)
	rec := multipartSend(t, s,
		part{"body", "", "", "look"},
		part{"media", "cat.jpg", "image/jpeg", "fakejpeg"},
		part{"media", "card.vcf", "", "BEGIN:VCARD\nEND:VCARD\n"}, // no type: sniffed as text/plain
	)
	if rec.Code != http.StatusCreated {
		t.Fatalf("send: %d %s", rec.Code, rec.Body)
	}
	sent := last.Load()
	if sent.Body == nil || *sent.Body != "look" || len(sent.Media) != 2 {
		t.Fatalf("sent %+v", sent)
	}
	for i, want := range []struct{ body, ctype string }{{"fakejpeg", "image/jpeg"}, {"BEGIN:VCARD\nEND:VCARD\n", "text/plain; charset=utf-8"}} {
		if !strings.HasPrefix(sent.Media[i], "https://sms.example.com/media-out/out-") {
			t.Fatalf("media url %q", sent.Media[i])
		}
		got := fetchAsSignalWire(t, s, sent.Media[i])
		if got.Code != 200 || got.Body.String() != want.body || got.Header().Get("Content-Type") != want.ctype {
			t.Fatalf("fetch %d: %d %q %v", i, got.Code, got.Body, got.Header())
		}
	}

	m := onlyMessage(t, s, "+16135551234")
	if len(m.Media) != 2 || m.Media[0].File == "" || m.Media[0].ServedType != "image/jpeg" || m.Media[0].Size != 8 ||
		m.Media[0].URL != sent.Media[0] {
		t.Fatalf("stored %+v", m.Media)
	}
	// Sent media is also available through the authenticated API.
	if rec := apiRequest(t, s, "GET", "/api/media/"+m.Media[0].File, ""); rec.Code != 200 || rec.Body.String() != "fakejpeg" {
		t.Fatalf("api media: %d", rec.Code)
	}
}

func TestSendMediaOnly(t *testing.T) {
	fake, last := fakeSignalWire(t, 201)
	s := newTestServer(t, fake.URL)
	if rec := multipartSend(t, s, part{"media", "a.png", "image/png", "png"}); rec.Code != http.StatusCreated {
		t.Fatalf("send: %d %s", rec.Code, rec.Body)
	}
	if sent := last.Load(); sent.Body != nil || len(sent.Media) != 1 {
		t.Fatalf("sent %+v", sent)
	}
	if m := onlyMessage(t, s, "+16135551234"); m.Body != nil {
		t.Fatalf("body %q", *m.Body)
	}
}

func TestSendForwardsStoredMedia(t *testing.T) {
	mediaSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/gif")
		w.Write([]byte("gif"))
	}))
	defer mediaSrv.Close()
	fake, last := fakeSignalWire(t, 201)
	s := newTestServer(t, fake.URL)
	useTLS(s, mediaSrv)
	signedPost(t, s, "/webhook/sms", inbound("in1", "+16135559999", "+16135550000", "",
		media{"url": mediaSrv.URL + "/g", "content_type": "image/gif", "size": 3}))
	s.wg.Wait()
	file := onlyMessage(t, s, "+16135559999").Media[0].File

	rec := apiRequest(t, s, "POST", "/api/numbers/%2B16135550000/conversations/%2B16135551234/messages",
		fmt.Sprintf(`{"body":"fwd","media_files":[%q]}`, file))
	if rec.Code != http.StatusCreated {
		t.Fatalf("forward: %d %s", rec.Code, rec.Body)
	}
	sent := last.Load()
	if len(sent.Media) != 1 {
		t.Fatalf("sent %+v", sent)
	}
	if got := fetchAsSignalWire(t, s, sent.Media[0]); got.Code != 200 || got.Body.String() != "gif" {
		t.Fatalf("fetch: %d", got.Code)
	}
	if m := onlyMessage(t, s, "+16135551234"); len(m.Media) != 1 || m.Media[0].File != file {
		t.Fatalf("stored %+v", m.Media)
	}

	// Multipart forwarding works too; unknown files are rejected.
	if rec := multipartSend(t, s, part{"media_files", "", "", file}); rec.Code != http.StatusCreated {
		t.Fatalf("multipart forward: %d %s", rec.Code, rec.Body)
	}
	if rec := apiRequest(t, s, "POST", "/api/numbers/%2B16135550000/conversations/%2B16135551234/messages", `{"media_files":["nope.jpg"]}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown file: %d", rec.Code)
	}
}

func TestSendRejectsBadMedia(t *testing.T) {
	fake, last := fakeSignalWire(t, 201)
	s := newTestServer(t, fake.URL)

	if rec := multipartSend(t, s, part{"media", "x.html", "text/html", "<script>"}); rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("html: %d", rec.Code)
	}
	if rec := multipartSend(t, s, part{"media", "x.bin", "", "\x00\x01\x02"}); rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("sniffed binary: %d", rec.Code)
	}
	var many []part
	for i := 0; i < maxSendMedia+1; i++ {
		many = append(many, part{"media", "a.png", "image/png", "png"})
	}
	if rec := multipartSend(t, s, many...); rec.Code != http.StatusBadRequest {
		t.Fatalf("too many: %d", rec.Code)
	}
	if rec := multipartSend(t, s, part{"media", "big.png", "image/png", strings.Repeat("x", maxUploadBytes)}); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("too big: %d", rec.Code)
	}
	if rec := multipartSend(t, s, part{"other", "", "", "x"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field: %d", rec.Code)
	}
	if rec := multipartSend(t, s, part{"body", "", "", "  "}); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty: %d", rec.Code)
	}
	if last.Load() != nil {
		t.Fatal("a bad request reached SignalWire")
	}
	if f := outFiles(t, s); len(f) != 0 {
		t.Fatalf("uploads left behind: %v", f)
	}
}

func TestSendFailureRemovesUploads(t *testing.T) {
	fake, _ := fakeSignalWire(t, 422)
	s := newTestServer(t, fake.URL)
	if rec := multipartSend(t, s, part{"media", "a.png", "image/png", "png"}); rec.Code != http.StatusBadGateway {
		t.Fatalf("send: %d", rec.Code)
	}
	if f := outFiles(t, s); len(f) != 0 {
		t.Fatalf("uploads left behind: %v", f)
	}
}

func TestMediaOutRejectsBadLinks(t *testing.T) {
	s := newTestServer(t, "")
	os.WriteFile(filepath.Join(s.cfg.MediaDir, "out-x.png"), []byte("png"), 0o600)
	m := outMedia{File: "out-x.png", Type: "image/png", Size: 3}
	good := s.mediaOutURL(m, time.Now())
	if rec := fetchAsSignalWire(t, s, good); rec.Code != 200 {
		t.Fatalf("good link: %d", rec.Code)
	}
	expired := s.mediaOutURL(m, time.Now().Add(-mediaOutValidFor-time.Minute))
	retyped := strings.Replace(good, "type=image%2Fpng", "type=text%2Fhtml", 1)
	renamed := strings.Replace(good, "out-x.png", "test.db", 1)
	for name, link := range map[string]string{
		"expired": expired, "retyped": retyped, "renamed": renamed,
		"no sig": good[:strings.Index(good, "&sig=")], "bad sig": good[:len(good)-2] + "00",
	} {
		if rec := fetchAsSignalWire(t, s, link); rec.Code != http.StatusForbidden {
			t.Errorf("%s: got %d", name, rec.Code)
		}
	}
}
