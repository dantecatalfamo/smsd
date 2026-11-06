// Command smsd is a minimal two-way SMS backend for a SignalWire number.
//
// It receives inbound messages via webhook, stores them in SQLite, threads
// them into conversations by the other party's number, and exposes a small
// authenticated JSON API for listing conversations and sending replies.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
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
	SkipSignature bool   // dev only
}

func loadConfig() config {
	c := config{
		Addr:          env("ADDR", ":8080"),
		PublicURL:     strings.TrimRight(os.Getenv("PUBLIC_URL"), "/"),
		DBPath:        env("DB_PATH", "smsd.db"),
		MediaDir:      env("MEDIA_DIR", "media"),
		Space:         os.Getenv("SW_SPACE"),
		ProjectID:     os.Getenv("SW_PROJECT_ID"),
		APIToken:      os.Getenv("SW_API_TOKEN"),
		SigningKey:    os.Getenv("SW_SIGNING_KEY"),
		FromNumber:    os.Getenv("SW_FROM_NUMBER"),
		AppToken:      os.Getenv("APP_TOKEN"),
		SkipSignature: os.Getenv("SKIP_SIGNATURE") == "1",
	}
	required := map[string]string{
		"PUBLIC_URL": c.PublicURL, "SW_SPACE": c.Space, "SW_PROJECT_ID": c.ProjectID,
		"SW_API_TOKEN": c.APIToken, "SW_FROM_NUMBER": c.FromNumber, "APP_TOKEN": c.AppToken,
	}
	if !c.SkipSignature {
		required["SW_SIGNING_KEY"] = c.SigningKey
	}
	for k, v := range required {
		if v == "" {
			log.Fatalf("missing required env var %s", k)
		}
	}
	return c
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	cfg := loadConfig()

	if err := os.MkdirAll(cfg.MediaDir, 0o750); err != nil {
		log.Fatalf("media dir: %v", err)
	}

	store, err := openStore(cfg.DBPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer store.Close()

	srv := &server{
		cfg:      cfg,
		store:    store,
		sw:       newSignalWire(cfg.Space, cfg.ProjectID, cfg.APIToken),
		notifier: logNotifier{},
	}

	httpSrv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
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
	srv.wg.Wait() // let in-flight media downloads finish
}
