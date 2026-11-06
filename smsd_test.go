package main

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestServer(t *testing.T, swURL string) *server {
	t.Helper()
	st, err := openStore(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg := config{
		PublicURL: "https://sms.example.com", SigningKey: "PSK_test", FromNumber: "+16135550000",
		AppToken: "secret", ProjectID: "proj", APIToken: "tok", MediaDir: t.TempDir(),
	}
	sw := newSignalWire("unused", "proj", "tok")
	if swURL != "" {
		sw.baseURL = swURL
	}
	return &server{cfg: cfg, store: st, sw: sw, notifier: logNotifier{}}
}

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
	return map[string]any{"message": msg, "params": map[string]any{}}
}

func TestInboundStoresAndDedupes(t *testing.T) {
	s := newTestServer(t, "")
	payload := inbound("m1", "+16135551234", "+16135550000", "hi")

	for i := 0; i < 2; i++ { // second is a retry of the same message_id
		rec := signedPost(t, s, "/webhook/sms", payload)
		if rec.Code != 200 || rec.Body.String() != receiveSWML {
			t.Fatalf("status %d: %s", rec.Code, rec.Body)
		}
	}

	msgs, err := s.store.Messages(t.Context(), "+16135551234", 0, 50)
	if err != nil || len(msgs) != 1 || msgs[0].Body != "hi" || msgs[0].SID != "m1" {
		t.Fatalf("got %+v, %v", msgs, err)
	}
	if want := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC); !msgs[0].CreatedAt.Equal(want) {
		t.Fatalf("created_at %v, want %v", msgs[0].CreatedAt, want)
	}
}

func TestInboundRejectsBadSignature(t *testing.T) {
	s := newTestServer(t, "")
	req := httptest.NewRequest("POST", "/webhook/sms", strings.NewReader(`{"message":{"message_id":"m1"}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SignalWire-Signature", "bogus")
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", rec.Code)
	}
}

func TestSendAndListConversation(t *testing.T) {
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
		w.Write([]byte(`{"id":"m2","status":"queued","kind":"sms"}`))
	}))
	defer fake.Close()
	s := newTestServer(t, fake.URL)
	h := s.routes()

	req := httptest.NewRequest("POST", "/api/conversations/%2B16135551234/messages", strings.NewReader(`{"body":"hello back"}`))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("send: %d %s", rec.Code, rec.Body)
	}

	req = httptest.NewRequest("GET", "/api/conversations", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var convs []Conversation
	json.Unmarshal(rec.Body.Bytes(), &convs)
	if len(convs) != 1 || convs[0].Peer != "+16135551234" || convs[0].LastDir != Outbound {
		t.Fatalf("conversations: %s", rec.Body)
	}

	if rec := signedPost(t, s, "/webhook/status", map[string]any{
		"id": "m2", "project_id": "proj", "status": "delivered", "to": "+16135551234", "from": "+16135550000",
		"body": "hello back", "number_of_segments": 1, "timestamp": "2026-11-05T12:00:01Z",
		"error_code": nil, "error_message": nil,
	}); rec.Code != http.StatusNoContent {
		t.Fatalf("status callback: %d %s", rec.Code, rec.Body)
	}
	if msgs, _ := s.store.Messages(t.Context(), "+16135551234", 0, 50); len(msgs) != 1 || msgs[0].Status != "delivered" {
		t.Fatalf("after status callback: %+v", msgs)
	}

	req = httptest.NewRequest("GET", "/api/conversations", nil) // no token
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
}

func TestSendReportsAPIError(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":[{"code":"invalid","message":"Invalid","detail":"to is not a valid number"}]}`, 422)
	}))
	defer fake.Close()
	s := newTestServer(t, fake.URL)
	req := httptest.NewRequest("POST", "/api/conversations/%2B16135551234/messages", strings.NewReader(`{"body":"x"}`))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "to is not a valid number") {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
}

func TestSignatureCase(t *testing.T) {
	body := []byte(`{"message":{}}`)
	mac := webhookMAC("PSK_test", "https://sms.example.com/webhook/sms", body)
	for _, sig := range []string{hex.EncodeToString(mac), strings.ToUpper(hex.EncodeToString(mac))} {
		if !validSignature("PSK_test", sig, "https://sms.example.com/webhook/sms", body) {
			t.Fatalf("rejected %s", sig)
		}
	}
	if validSignature("PSK_test", hex.EncodeToString(mac), "https://sms.example.com/webhook/sms", []byte(`{"message":{"x":1}}`)) {
		t.Fatal("accepted signature for a different body")
	}
	if validSignature("PSK_test", "", "https://sms.example.com/webhook/sms", body) {
		t.Fatal("accepted empty signature")
	}
}

// The status callback can arrive before handleSend has stored the message.
func TestStatusBeforeInsertIsKept(t *testing.T) {
	s := newTestServer(t, "")
	ctx := t.Context()
	if err := s.store.UpdateStatus(ctx, "SM3", "delivered"); err != nil {
		t.Fatal(err)
	}
	m := Message{SID: "SM3", Direction: Outbound, Peer: "+16135551234", Body: "x", Status: "queued", CreatedAt: time.Now()}
	if _, err := s.store.Insert(ctx, &m); err != nil {
		t.Fatal(err)
	}
	if m.Status != "delivered" {
		t.Fatalf("returned status %q", m.Status)
	}
	msgs, _ := s.store.Messages(ctx, "+16135551234", 0, 50)
	if len(msgs) != 1 || msgs[0].Status != "delivered" {
		t.Fatalf("got %+v", msgs)
	}
	var n int
	s.store.db.QueryRow(`SELECT COUNT(*) FROM pending_status`).Scan(&n)
	if n != 0 {
		t.Fatalf("pending_status not cleared: %d rows", n)
	}
}

func TestInboundIgnoresOtherNumbers(t *testing.T) {
	s := newTestServer(t, "")
	if rec := signedPost(t, s, "/webhook/sms", inbound("m4", "+16135551234", "+16135559999", "hi")); rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if msgs, _ := s.store.Messages(t.Context(), "+16135551234", 0, 50); len(msgs) != 0 {
		t.Fatalf("stored message for another number: %+v", msgs)
	}
}

func TestInboundRequiresSID(t *testing.T) {
	s := newTestServer(t, "")
	if rec := signedPost(t, s, "/webhook/sms", inbound("", "+16135551234", "+16135550000", "hi")); rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

func TestInboundMediaSavedLocally(t *testing.T) {
	mediaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/jpeg")
		w.Write([]byte("fakejpeg"))
	}))
	defer mediaSrv.Close()
	s := newTestServer(t, "")
	payload := inbound("SM5", "+16135551234", "+16135550000", "",
		media{"url": mediaSrv.URL + "/m/1", "content_type": "image/jpeg", "size": 8})
	if rec := signedPost(t, s, "/webhook/sms", payload); rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	s.wg.Wait()

	msgs, _ := s.store.Messages(t.Context(), "+16135551234", 0, 50)
	if len(msgs) != 1 || len(msgs[0].MediaFiles) != 1 || msgs[0].MediaFiles[0] != "SM5-0.jpg" {
		t.Fatalf("got %+v", msgs)
	}
	if b, err := os.ReadFile(filepath.Join(s.cfg.MediaDir, "SM5-0.jpg")); err != nil || string(b) != "fakejpeg" {
		t.Fatalf("file: %q %v", b, err)
	}

	h := s.routes()
	req := httptest.NewRequest("GET", "/api/media/SM5-0.jpg", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || rec.Body.String() != "fakejpeg" {
		t.Fatalf("serve: %d %q", rec.Code, rec.Body)
	}
	req = httptest.NewRequest("GET", "/api/media/..%2Ftest.db", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("traversal: want 404, got %d", rec.Code)
	}
}

func TestMigratesOldSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	st, err := openStore(path)
	if err != nil {
		t.Fatal(err)
	}
	// Recreate the table as it was before media_files existed.
	if _, err := st.db.Exec(`DROP TABLE messages; CREATE TABLE messages (id INTEGER PRIMARY KEY, sid TEXT UNIQUE,
		direction TEXT NOT NULL, peer TEXT NOT NULL, body TEXT NOT NULL, media TEXT NOT NULL DEFAULT '[]',
		status TEXT NOT NULL, created_at INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	st.Close()

	st, err = openStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	m := Message{SID: "SM6", Direction: Inbound, Peer: "+16135551234", Body: "x", Status: "received", CreatedAt: time.Now()}
	if _, err := st.Insert(t.Context(), &m); err != nil {
		t.Fatal(err)
	}
	if msgs, err := st.Messages(t.Context(), "+16135551234", 0, 50); err != nil || len(msgs) != 1 {
		t.Fatalf("got %+v, %v", msgs, err)
	}
}
