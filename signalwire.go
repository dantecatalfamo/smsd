package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// signalWire is a tiny client for SignalWire's native messaging REST API.
type signalWire struct {
	baseURL   string // e.g. https://example.signalwire.com/api/messaging
	space     string
	projectID string
	apiToken  string
	http      *http.Client
	media     *http.Client // longer timeout for MMS downloads
}

func newSignalWire(space, projectID, apiToken string) *signalWire {
	return &signalWire{
		baseURL:   fmt.Sprintf("https://%s/api/messaging", space),
		space:     space,
		projectID: projectID,
		apiToken:  apiToken,
		http:      &http.Client{Timeout: 15 * time.Second},
		media:     &http.Client{Timeout: 60 * time.Second},
	}
}

type sendResult struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

type apiError struct {
	Status  int
	Message string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("signalwire: %d: %s", e.Status, e.Message)
}

func parseAPIError(status int, raw []byte) *apiError {
	var body struct {
		Message string `json:"message"`
		Errors  []struct {
			Message string `json:"message"`
			Detail  string `json:"detail"`
		} `json:"errors"`
	}
	msg := ""
	if json.Unmarshal(raw, &body) == nil {
		msg = body.Message
		if msg == "" && len(body.Errors) > 0 {
			if msg = body.Errors[0].Detail; msg == "" {
				msg = body.Errors[0].Message
			}
		}
	}
	if msg == "" {
		msg = strings.TrimSpace(string(raw))
	}
	return &apiError{Status: status, Message: msg}
}

// Send creates an outbound SMS. statusCallback may be empty.
func (c *signalWire) Send(ctx context.Context, from, to, body, statusCallback string) (*sendResult, error) {
	payload, err := json.Marshal(struct {
		From           string `json:"from"`
		To             string `json:"to"`
		Body           string `json:"body"`
		StatusCallback string `json:"status_callback,omitempty"`
	}{from, to, body, statusCallback})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/messages", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.projectID, c.apiToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode/100 != 2 {
		return nil, parseAPIError(resp.StatusCode, raw)
	}

	var out sendResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode send response: %w", err)
	}
	if out.ID == "" {
		return nil, fmt.Errorf("send response has no message id: %s", raw)
	}
	return &out, nil
}

// Fetch GETs a media URL from an inbound MMS. Credentials are only sent to our
// own space; media can also be served from elsewhere (e.g. a CDN). The http
// client drops them on cross-host redirects.
func (c *signalWire) Fetch(ctx context.Context, rawURL string) (*http.Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("unsupported media URL scheme %q", u.Scheme)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	if u.Host == c.space {
		req.SetBasicAuth(c.projectID, c.apiToken)
	}
	return c.media.Do(req)
}

// webhookMAC is SignalWire's signature for JSON webhooks (SWML document
// fetches, status callbacks): HMAC-SHA1(signing key, url + raw body).
func webhookMAC(key, fullURL string, body []byte) []byte {
	mac := hmac.New(sha1.New, []byte(key))
	mac.Write([]byte(fullURL))
	mac.Write(body)
	return mac.Sum(nil)
}

// validSignature checks a hex X-SignalWire-Signature header, matching
// validateRequest in SignalWire's @signalwire/web-api package.
func validSignature(key, signature, fullURL string, body []byte) bool {
	if signature == "" {
		return false
	}
	want := hex.EncodeToString(webhookMAC(key, fullURL, body))
	return hmac.Equal([]byte(want), []byte(strings.ToLower(signature)))
}
