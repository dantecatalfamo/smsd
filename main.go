// Command smsd is a minimal two-way SMS backend for a SignalWire number.
//
// It receives inbound messages via webhook, stores them in SQLite, threads
// them into conversations by the other party's number, and exposes a small
// authenticated JSON API for listing conversations and sending replies.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"
)

type config struct {
	Addr          string // listen address, e.g. ":8080"
	PublicURL     string // public base URL SignalWire calls, e.g. "https://sms.example.com" (used for signatures)
	DBPath        string
	MediaDir      string // where inbound MMS media is saved
	Space         string // e.g. "example.signalwire.com"
	ProjectID     string
	APIToken      string
	SigningKey    string // from the API Credentials page; used to verify webhooks
	FromNumber    string // your SignalWire number in E.164
	AppToken      string // bearer token protecting /api/*
	SkipSignature bool   // dev only; requires a loopback ADDR
}

var e164 = regexp.MustCompile(`^\+[1-9]\d{6,14}$`)

func loadConfig(getenv func(string) string) (config, error) {
	env := func(key, def string) string {
		if v := getenv(key); v != "" {
			return v
		}
		return def
	}
	c := config{
		Addr:          env("ADDR", ":8080"),
		PublicURL:     strings.TrimRight(getenv("PUBLIC_URL"), "/"),
		DBPath:        env("DB_PATH", "smsd.db"),
		MediaDir:      env("MEDIA_DIR", "media"),
		Space:         getenv("SW_SPACE"),
		ProjectID:     getenv("SW_PROJECT_ID"),
		APIToken:      getenv("SW_API_TOKEN"),
		SigningKey:    getenv("SW_SIGNING_KEY"),
		FromNumber:    getenv("SW_FROM_NUMBER"),
		AppToken:      getenv("APP_TOKEN"),
		SkipSignature: getenv("SKIP_SIGNATURE") == "1",
	}
	required := map[string]string{
		"PUBLIC_URL": c.PublicURL, "SW_SPACE": c.Space, "SW_PROJECT_ID": c.ProjectID,
		"SW_API_TOKEN": c.APIToken, "SW_FROM_NUMBER": c.FromNumber, "APP_TOKEN": c.AppToken,
	}
	if !c.SkipSignature {
		required["SW_SIGNING_KEY"] = c.SigningKey
	}
	var missing []string
	for k, v := range required {
		if v == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return c, fmt.Errorf("missing required env vars: %s", strings.Join(missing, ", "))
	}

	// PUBLIC_URL is part of every signature check and the status callback URL.
	// A path prefix is fine (for a prefix-stripping proxy); query, fragment and
	// credentials are not.
	u, err := url.Parse(c.PublicURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" ||
		u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return c, fmt.Errorf("PUBLIC_URL must be like https://sms.example.com, got %q", c.PublicURL)
	}
	if strings.ContainsAny(c.Space, "/:") {
		return c, fmt.Errorf("SW_SPACE must be a host name like example.signalwire.com, got %q", c.Space)
	}
	if !e164.MatchString(c.FromNumber) {
		return c, fmt.Errorf("SW_FROM_NUMBER must be E.164 like +16135550000, got %q", c.FromNumber)
	}
	if c.SkipSignature {
		host, _, err := net.SplitHostPort(c.Addr)
		ip := net.ParseIP(host)
		if err != nil || (host != "localhost" && (ip == nil || !ip.IsLoopback())) {
			return c, fmt.Errorf("SKIP_SIGNATURE=1 needs a loopback ADDR like 127.0.0.1:8080, got %q", c.Addr)
		}
	}
	return c, nil
}

func main() {
	cfg, err := loadConfig(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	if cfg.SkipSignature {
		log.Printf("WARNING: SKIP_SIGNATURE=1, webhooks are NOT authenticated")
	}

	if err := os.MkdirAll(cfg.MediaDir, 0o750); err != nil {
		log.Fatalf("media dir: %v", err)
	}
	if err := cleanMediaDir(cfg.MediaDir); err != nil {
		log.Fatalf("clean media dir: %v", err)
	}

	store, err := openStore(cfg.DBPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer store.Close()

	srv := newServer(cfg, store, newSignalWire(cfg.Space, cfg.ProjectID, cfg.APIToken), logNotifier{})

	// Retry downloads that failed or were interrupted, while the URLs are likely still valid.
	srv.background(func(ctx context.Context) {
		jobs, err := store.MissingMedia(ctx, time.Now().Add(-mediaRetryAge))
		if err != nil {
			log.Printf("list missing media: %v", err)
			return
		}
		if len(jobs) > 0 {
			log.Printf("retrying %d media downloads", len(jobs))
		}
		srv.saveMedia(ctx, jobs)
	})

	httpSrv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second, // /api/media extends its own deadline
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		log.Printf("listening on %s", cfg.Addr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown: %v", err)
	}
	srv.stop() // cancels downloads; unfinished ones are retried on next start
}
