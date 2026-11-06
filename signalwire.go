package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// signalWire is a tiny client for the Compatibility (LaML) REST API.
type signalWire struct {
	baseURL   string
	space     string
	projectID string
	apiToken  string
	http      *http.Client
	media     *http.Client // longer timeout for MMS downloads
}

func newSignalWire(space, projectID, apiToken string) *signalWire {
	return &signalWire{
		baseURL:   fmt.Sprintf("https://%s/api/laml/2010-04-01/Accounts/%s", space, projectID),
		space:     space,
		projectID: projectID,
		apiToken:  apiToken,
		http:      &http.Client{Timeout: 15 * time.Second},
		media:     &http.Client{Timeout: 60 * time.Second},
	}
}

type sendResult struct {
	SID    string `json:"sid"`
	Status string `json:"status"`
}

type apiError struct {
	Status  int    `json:"status"`
	Code    any    `json:"code"`
	Message string `json:"message"`
}

func (e *apiError) Error() string {
	return fmt.Sprintf("signalwire: %d %v: %s", e.Status, e.Code, e.Message)
}

// Send creates an outbound SMS. statusCallback may be empty.
func (c *signalWire) Send(ctx context.Context, from, to, body, statusCallback string) (*sendResult, error) {
	form := url.Values{"From": {from}, "To": {to}, "Body": {body}}
	if statusCallback != "" {
		form.Set("StatusCallback", statusCallback)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/Messages.json", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.projectID, c.apiToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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
		e := &apiError{Status: resp.StatusCode}
		if json.Unmarshal(raw, e) != nil || e.Message == "" {
			e.Message = strings.TrimSpace(string(raw))
		}
		return nil, e
	}

	var out sendResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode send response: %w", err)
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

// computeSignature implements the Compatibility API (Twilio-style) webhook
// signature: base64(HMAC-SHA1(key, fullURL + sorted(name+value...))).
func computeSignature(key, fullURL string, params url.Values) string {
	var b strings.Builder
	b.WriteString(fullURL)

	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		vals := append([]string(nil), params[k]...)
		sort.Strings(vals)
		for _, v := range vals {
			b.WriteString(k)
			b.WriteString(v)
		}
	}

	mac := hmac.New(sha1.New, []byte(key))
	mac.Write([]byte(b.String()))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func validSignature(key, signature, fullURL string, params url.Values) bool {
	if signature == "" {
		return false
	}
	expected := computeSignature(key, fullURL, params)
	return hmac.Equal([]byte(expected), []byte(signature))
}
