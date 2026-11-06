package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	http      *http.Client // timeouts come from each call's context
}

var sendTimeout = 15 * time.Second // var for tests

func newSignalWire(space, projectID, apiToken string) *signalWire {
	c := &signalWire{
		baseURL:   fmt.Sprintf("https://%s/api/messaging", space),
		space:     space,
		projectID: projectID,
		apiToken:  apiToken,
	}
	c.http = &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		// Go keeps Authorization on same-host redirects even when the port or
		// scheme changes; only keep it for https to our own space.
		if !c.ownSpace(req.URL) {
			req.Header.Del("Authorization")
		}
		return nil
	}}
	return c
}

// ownSpace reports whether credentials may be sent to u.
func (c *signalWire) ownSpace(u *url.URL) bool {
	return u.Scheme == "https" && strings.EqualFold(u.Host, c.space)
}

// sendResult is the create-message response.
type sendResult struct {
	ID               string          `json:"id"`
	ProjectID        string          `json:"project_id"`
	Status           string          `json:"status"`
	Kind             string          `json:"kind"` // sms, mms, whatsapp
	NumberOfSegments *int            `json:"number_of_segments"`
	ErrorCode        json.RawMessage `json:"error_code"`
	ErrorMessage     *string         `json:"error_message"`
	CreatedAt        string          `json:"created_at"`

	Raw json.RawMessage `json:"-"` // the whole response, stored with the message
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

// Send creates an outbound SMS, or MMS when media URLs are given. body may be
// empty if there is media; statusCallback may be empty.
func (c *signalWire) Send(ctx context.Context, from, to, body string, media []string, statusCallback string) (*sendResult, error) {
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	payload, err := json.Marshal(struct {
		From           string   `json:"from"`
		To             string   `json:"to"`
		Body           string   `json:"body,omitempty"`
		Media          []string `json:"media,omitempty"`
		StatusCallback string   `json:"status_callback,omitempty"`
	}{from, to, body, media, statusCallback})
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
	out.Raw = raw
	return &out, nil
}

// Fetch GETs a media URL from an inbound MMS. Only https is allowed, and
// credentials only go to our own space (media can also be served from a CDN).
func (c *signalWire) Fetch(ctx context.Context, rawURL string) (*http.Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("refusing non-https media URL %q", rawURL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	if c.ownSpace(u) {
		req.SetBasicAuth(c.projectID, c.apiToken)
	}
	return c.http.Do(req)
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
// validateRequest in SignalWire's @signalwire/web-api package. Empty or
// non-hex signatures fail to decode and are rejected.
func validSignature(key, signature, fullURL string, body []byte) bool {
	got, err := hex.DecodeString(signature)
	return err == nil && hmac.Equal(got, webhookMAC(key, fullURL, body))
}
