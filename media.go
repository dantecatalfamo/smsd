package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
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
	h := w.Header()
	h.Set("Content-Type", ct)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "sandbox") // no scripts even if a type slips through
	if !servedInline(ct) {
		h.Set("Content-Disposition", "attachment")
	}
	// Large files on slow links outlast the server-wide WriteTimeout.
	err = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(10 * time.Minute))
	if err != nil && !errors.Is(err, http.ErrNotSupported) {
		log.Printf("media %q: extend write deadline: %v", name, err)
	}
	http.ServeFile(w, r, filepath.Join(s.cfg.MediaDir, name))
}
