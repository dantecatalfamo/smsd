package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func signedInbound(t *testing.T, s *server, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/webhook/sms", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-SignalWire-Signature", computeSignature(s.cfg.SigningKey, s.cfg.PublicURL+"/webhook/sms", form))
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	return rec
}

func TestInboundStoresAndDedupes(t *testing.T) {
	s := newTestServer(t, "")
	form := url.Values{"MessageSid": {"SM1"}, "From": {"+16135551234"}, "To": {"+16135550000"}, "Body": {"hi"}}

	for i := 0; i < 2; i++ { // second is a retry of the same SID
		if rec := signedInbound(t, s, form); rec.Code != 200 {
			t.Fatalf("status %d: %s", rec.Code, rec.Body)
		}
	}

	msgs, err := s.store.Messages(t.Context(), "+16135551234", 0, 50)
	if err != nil || len(msgs) != 1 || msgs[0].Body != "hi" {
		t.Fatalf("got %+v, %v", msgs, err)
	}
}

func TestInboundRejectsBadSignature(t *testing.T) {
	s := newTestServer(t, "")
	req := httptest.NewRequest("POST", "/webhook/sms", strings.NewReader("From=%2B1&Body=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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
		r.ParseForm()
		if r.URL.Path != "/Messages.json" || u != "proj" || p != "tok" || r.PostForm.Get("To") != "+16135551234" {
			http.Error(w, `{"message":"bad"}`, 400)
			return
		}
		w.Write([]byte(`{"sid":"SM2","status":"queued"}`))
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

	req = httptest.NewRequest("GET", "/api/conversations", nil) // no token
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
}

// Published Twilio test vector; SignalWire's Compatibility API uses the same scheme.
func TestSignatureKnownVector(t *testing.T) {
	p := url.Values{"CallSid": {"CA1234567890ABCDE"}, "Caller": {"+12349013030"}, "Digits": {"1234"}, "From": {"+12349013030"}, "To": {"+18005551212"}}
	if got := computeSignature("12345", "https://mycompany.com/myapp.php?foo=1&bar=2", p); got != "0/KCTR6DLpKmkAf8muzZqo1nDgQ=" {
		t.Fatalf("got %s", got)
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
	form := url.Values{"MessageSid": {"SM4"}, "From": {"+16135551234"}, "To": {"+16135559999"}, "Body": {"hi"}}
	if rec := signedInbound(t, s, form); rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if msgs, _ := s.store.Messages(t.Context(), "+16135551234", 0, 50); len(msgs) != 0 {
		t.Fatalf("stored message for another number: %+v", msgs)
	}
}

func TestInboundRequiresSID(t *testing.T) {
	s := newTestServer(t, "")
	form := url.Values{"From": {"+16135551234"}, "To": {"+16135550000"}, "Body": {"hi"}}
	if rec := signedInbound(t, s, form); rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

func TestInboundMediaSavedLocally(t *testing.T) {
	media := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/jpeg")
		w.Write([]byte("fakejpeg"))
	}))
	defer media.Close()
	s := newTestServer(t, "")
	form := url.Values{"MessageSid": {"SM5"}, "From": {"+16135551234"}, "To": {"+16135550000"}, "Body": {""},
		"NumMedia": {"1"}, "MediaUrl0": {media.URL + "/m/1"}}
	if rec := signedInbound(t, s, form); rec.Code != 200 {
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
