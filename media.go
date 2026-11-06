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
// the provider's URLs, then records the local file names on the message.
func (s *server) saveMedia(ctx context.Context, m Message) {
	var files []string
	for i, u := range m.Media {
		name, err := s.downloadMedia(ctx, u, fmt.Sprintf("%s-%d", m.SID, i))
		if err != nil {
			log.Printf("media %s[%d]: %v", m.SID, i, err)
			continue
		}
		files = append(files, name)
	}
	if len(files) == 0 {
		return
	}
	if err := s.store.SetMediaFiles(ctx, m.ID, files); err != nil {
		log.Printf("store media files for %s: %v", m.SID, err)
	}
}

func (s *server) downloadMedia(ctx context.Context, rawURL, base string) (string, error) {
	resp, err := s.sw.Fetch(ctx, rawURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch: status %d", resp.StatusCode)
	}

	ext := ""
	if ct, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err == nil {
		if e, ok := mediaExt[ct]; ok {
			ext = e
		} else if exts, _ := mime.ExtensionsByType(ct); len(exts) > 0 {
			ext = exts[0]
		}
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
