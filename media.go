package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
)

const maxMediaBytes = 25 << 20

// safeName matches the file names saveMedia writes, and is the only shape
// /api/media/{name} will serve.
var safeName = regexp.MustCompile(`^[A-Za-z0-9_-]+(\.[A-Za-z0-9]+)?$`)

// Preferred extensions where mime.ExtensionsByType's first pick is odd (.jfif).
var mediaExt = map[string]string{"image/jpeg": ".jpg", "image/png": ".png", "image/gif": ".gif", "video/mp4": ".mp4"}

// saveMedia downloads an inbound message's media into MediaDir so it outlives
// SignalWire's URLs, recording each local file name as it lands.
func (s *server) saveMedia(ctx context.Context, m Message) {
	for i, md := range m.Media {
		if md.URL == "" {
			continue
		}
		if md.Size > maxMediaBytes {
			log.Printf("media %s[%d]: skipping, SignalWire reports %d bytes (limit %d)", m.SignalWireID, i, md.Size, maxMediaBytes)
			continue
		}
		name, err := s.downloadMedia(ctx, md, fmt.Sprintf("%s-%d", m.SignalWireID, i))
		if err != nil {
			log.Printf("media %s[%d]: %v", m.SignalWireID, i, err)
			continue
		}
		if err := s.store.SetMediaFile(ctx, m.ID, i, name); err != nil {
			log.Printf("store media file for %s[%d]: %v", m.SignalWireID, i, err)
		}
	}
}

func (s *server) downloadMedia(ctx context.Context, md Media, base string) (string, error) {
	resp, err := s.sw.Fetch(ctx, md.URL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch: status %d", resp.StatusCode)
	}

	// Trust the download's own type first; fall back to what the webhook declared.
	ct, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || ct == "application/octet-stream" {
		ct, _, _ = mime.ParseMediaType(md.ContentType)
	}
	ext := ""
	if e, ok := mediaExt[ct]; ok {
		ext = e
	} else if exts, _ := mime.ExtensionsByType(ct); len(exts) > 0 {
		ext = exts[0]
	}
	name := base + ext
	if !safeName.MatchString(name) {
		return "", fmt.Errorf("unsafe file name %q", name)
	}

	// Write to a temp file and rename, so a partial download never shows up under its real name.
	f, err := os.CreateTemp(s.cfg.MediaDir, ".download-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name()) // no-op after a successful rename
	n, err := io.Copy(f, io.LimitReader(resp.Body, maxMediaBytes+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	if n > maxMediaBytes {
		return "", fmt.Errorf("larger than %d bytes", maxMediaBytes)
	}
	if err := os.Rename(f.Name(), filepath.Join(s.cfg.MediaDir, name)); err != nil {
		return "", err
	}
	return name, nil
}

func (s *server) handleMedia(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !safeName.MatchString(name) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeFile(w, r, filepath.Join(s.cfg.MediaDir, name))
}
