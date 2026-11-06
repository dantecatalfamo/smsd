package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	maxMediaBytes   = 25 << 20
	mediaTimeout    = 60 * time.Second // per attachment
	mediaRetryAge   = 72 * time.Hour   // at startup, retry failed downloads this recent
	tempMediaPrefix = ".download-"
)

// mediaExt names saved files for humans; it never decides how a file is
// served. Types are SignalWire's supported MMS types plus common phone
// formats. Anything else is saved without an extension.
var mediaExt = map[string]string{
	"image/jpeg": ".jpg", "image/png": ".png", "image/gif": ".gif", "image/bmp": ".bmp",
	"image/webp": ".webp", "image/heic": ".heic", "image/heif": ".heif",
	"audio/mp4": ".m4a", "audio/mpeg": ".mp3", "audio/mpeg3": ".mp3", "audio/ogg": ".ogg",
	"audio/vorbis": ".ogg", "audio/vnd.wav": ".wav", "audio/wav": ".wav", "audio/ac3": ".ac3",
	"audio/amr": ".amr", "audio/midi": ".mid",
	"video/mpeg": ".mpeg", "video/mp4": ".mp4", "video/quicktime": ".mov", "video/h264": ".h264",
	"video/3gp": ".3gp", "video/3gpp": ".3gp",
	"text/plain": ".txt", "text/calendar": ".ics", "text/vcard": ".vcf", "text/x-vcard": ".vcf",
}

// inlineImages are the image types a browser may display in place. Every other
// type except audio/* and video/* (HTML, SVG, text, vCards...) is served as a download.
var inlineImages = map[string]bool{
	"image/jpeg": true, "image/png": true, "image/gif": true, "image/bmp": true,
	"image/webp": true, "image/heic": true, "image/heif": true,
}

func servedInline(contentType string) bool {
	t, _, _ := mime.ParseMediaType(contentType)
	return inlineImages[t] || strings.HasPrefix(t, "audio/") || strings.HasPrefix(t, "video/")
}

// saveMedia downloads attachments into MediaDir so they outlive SignalWire's
// URLs, recording each local file as it lands. Each gets its own timeout.
func (s *server) saveMedia(ctx context.Context, jobs []mediaJob) {
	for _, j := range jobs {
		if ctx.Err() != nil {
			return // shutting down; MissingMedia picks these up next start
		}
		if j.URL == "" {
			continue
		}
		if j.Size > maxMediaBytes {
			log.Printf("media %d[%d]: skipping, SignalWire reports %d bytes (limit %d)", j.MessageID, j.Position, j.Size, maxMediaBytes)
			continue
		}
		if err := s.downloadMedia(ctx, j); err != nil {
			log.Printf("media %d[%d]: %v", j.MessageID, j.Position, err)
		}
	}
}

func (s *server) downloadMedia(ctx context.Context, j mediaJob) error {
	ctx, cancel := context.WithTimeout(ctx, mediaTimeout)
	defer cancel()

	resp, err := s.sw.Fetch(ctx, j.URL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch: status %d", resp.StatusCode)
	}

	// Prefer the download's own type; fall back to what the webhook declared.
	t, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || t == "application/octet-stream" {
		if t2, p2, err2 := mime.ParseMediaType(j.ContentType); err2 == nil {
			t, params, err = t2, p2, nil
		}
	}
	servedType := "application/octet-stream"
	if err == nil {
		servedType = mime.FormatMediaType(t, params)
	}
	// Names come only from our own integer ids, so they're always safe to use as paths.
	name := fmt.Sprintf("%d-%d%s", j.MessageID, j.Position, mediaExt[t])

	// Write to a temp file and rename, so a partial download never shows up under its real name.
	f, err := os.CreateTemp(s.cfg.MediaDir, tempMediaPrefix+"*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name()) // no-op after a successful rename
	n, err := io.Copy(f, io.LimitReader(resp.Body, maxMediaBytes+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n > maxMediaBytes {
		return fmt.Errorf("larger than %d bytes", maxMediaBytes)
	}
	if err := os.Rename(f.Name(), filepath.Join(s.cfg.MediaDir, name)); err != nil {
		return err
	}
	return s.store.SetMediaFile(ctx, j.MessageID, j.Position, name, servedType)
}

// cleanMediaDir removes temp files left by downloads interrupted by a crash.
func cleanMediaDir(dir string) error {
	tmp, err := filepath.Glob(filepath.Join(dir, tempMediaPrefix+"*"))
	if err != nil {
		return err
	}
	for _, p := range tmp {
		if err := os.Remove(p); err != nil {
			return err
		}
	}
	return nil
}

// handleMedia serves only files smsd downloaded, with the type recorded at
// download time. Nothing is inferred from the name or the content.
func (s *server) handleMedia(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	ct, err := s.store.MediaServedType(r.Context(), name)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		log.Printf("media lookup %q: %v", name, err)
		writeJSON(w, http.StatusInternalServerError, errBody("internal error"))
		return
	}
	serveMediaFile(w, r, filepath.Join(s.cfg.MediaDir, name), ct)
}

// serveMediaFile serves a media file with a fixed type. Nothing is inferred
// from the name or the content.
func serveMediaFile(w http.ResponseWriter, r *http.Request, path, contentType string) {
	h := w.Header()
	h.Set("Content-Type", contentType)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "sandbox") // no scripts even if a type slips through
	if !servedInline(contentType) {
		h.Set("Content-Disposition", "attachment")
	}
	// Large files on slow links outlast the server-wide WriteTimeout.
	err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(10 * time.Minute))
	if err != nil && !errors.Is(err, http.ErrNotSupported) {
		log.Printf("media %q: extend write deadline: %v", path, err)
	}
	http.ServeFile(w, r, path)
}

// --- outbound media ---------------------------------------------------------

const (
	maxSendMedia     = 7       // SignalWire's limit per message
	maxUploadBytes   = 5 << 20 // per request; SignalWire delivers ~1.2 MB total anyway
	mediaOutValidFor = 24 * time.Hour
)

// sendableTypes are the MMS types SignalWire accepts
// (https://signalwire.com/docs/platform/messaging/mime-types).
var sendableTypes = map[string]bool{
	"audio/mp4": true, "audio/mpeg": true, "audio/mpeg3": true, "audio/ogg": true, "audio/vorbis": true,
	"audio/vnd.wav": true, "audio/ac3": true, "audio/amr": true, "audio/midi": true,
	"image/jpeg": true, "image/gif": true, "image/png": true, "image/bmp": true,
	"text/plain": true, "text/calendar": true, "text/vcard": true, "text/x-vcard": true,
	"video/mpeg": true, "video/mp4": true, "video/quicktime": true, "video/h264": true, "video/3gp": true,
}

func sendable(contentType string) bool {
	t, _, _ := mime.ParseMediaType(contentType)
	return sendableTypes[t]
}

// outMedia is a local file to attach to an outgoing message.
type outMedia struct {
	File string
	Type string
	Size int64
}

// saveUpload stores one uploaded file in MediaDir under a random name. The
// type comes from the part's Content-Type, or is sniffed if that's missing.
func (s *server) saveUpload(p io.Reader, declared string) (outMedia, error) {
	head := make([]byte, 512)
	n, err := io.ReadFull(p, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return outMedia{}, err
	}
	head = head[:n]
	t, params, err := mime.ParseMediaType(declared)
	if err != nil || t == "application/octet-stream" {
		t, params, _ = mime.ParseMediaType(http.DetectContentType(head))
	}
	if !sendableTypes[t] {
		return outMedia{}, &httpError{http.StatusUnsupportedMediaType, fmt.Sprintf("can't send media of type %q", t)}
	}

	f, err := os.CreateTemp(s.cfg.MediaDir, tempMediaPrefix+"*")
	if err != nil {
		return outMedia{}, err
	}
	defer os.Remove(f.Name()) // no-op after a successful rename
	size, err := io.Copy(f, io.MultiReader(bytes.NewReader(head), p))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return outMedia{}, err
	}
	name := "out-" + strings.ToLower(rand.Text()) + mediaExt[t]
	if err := os.Rename(f.Name(), filepath.Join(s.cfg.MediaDir, name)); err != nil {
		return outMedia{}, err
	}
	return outMedia{File: name, Type: mime.FormatMediaType(t, params), Size: size}, nil
}

// storedMedia looks up a file smsd already has (e.g. a received attachment) for forwarding.
func (s *server) storedMedia(ctx context.Context, name string) (outMedia, error) {
	ct, err := s.store.MediaServedType(ctx, name)
	if errors.Is(err, sql.ErrNoRows) {
		return outMedia{}, &httpError{http.StatusBadRequest, fmt.Sprintf("no media file %q", name)}
	}
	if err != nil {
		return outMedia{}, err
	}
	if !sendable(ct) {
		return outMedia{}, &httpError{http.StatusUnsupportedMediaType, fmt.Sprintf("can't send media of type %q", ct)}
	}
	fi, err := os.Stat(filepath.Join(s.cfg.MediaDir, name))
	if err != nil {
		return outMedia{}, err
	}
	return outMedia{File: name, Type: ct, Size: fi.Size()}, nil
}

// mediaOutSig signs a /media-out/ link. The type is part of the link so the
// route needs no database row: SignalWire may fetch before the message is stored.
func (s *server) mediaOutSig(name, contentType, exp string) []byte {
	mac := hmac.New(sha256.New, s.mediaKey)
	mac.Write([]byte(name + "\n" + contentType + "\n" + exp))
	return mac.Sum(nil)
}

// mediaOutURL is a public link SignalWire can fetch an outgoing attachment from.
func (s *server) mediaOutURL(m outMedia, now time.Time) string {
	exp := strconv.FormatInt(now.Add(mediaOutValidFor).Unix(), 10)
	q := url.Values{"type": {m.Type}, "exp": {exp}, "sig": {hex.EncodeToString(s.mediaOutSig(m.File, m.Type, exp))}}
	return s.cfg.PublicURL + "/media-out/" + url.PathEscape(m.File) + "?" + q.Encode()
}

// handleMediaOut serves outgoing attachments to SignalWire. It's public, so
// it serves only what a valid, unexpired signed link names.
func (s *server) handleMediaOut(w http.ResponseWriter, r *http.Request) {
	name, q := r.PathValue("name"), r.URL.Query()
	ct, exp := q.Get("type"), q.Get("exp")
	sig, err := hex.DecodeString(q.Get("sig"))
	expAt, perr := strconv.ParseInt(exp, 10, 64)
	if err != nil || perr != nil || time.Now().Unix() > expAt || !hmac.Equal(sig, s.mediaOutSig(name, ct, exp)) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	serveMediaFile(w, r, filepath.Join(s.cfg.MediaDir, name), ct)
}
