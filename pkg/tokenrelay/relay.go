package tokenrelay

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

const maxBodySize = 64 * 1024

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// Handler proxies token acquisition requests to the upstream endpoint and
// logs each request for visibility. Caching will be added in a follow-up.
type Handler struct {
	upstreamURL string
	httpClient  *http.Client
}

func NewHandler(upstreamTokenURL string) *Handler {
	return &Handler{
		upstreamURL: upstreamTokenURL,
		httpClient:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize))
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	clientID := extractClientID(body, r.Header.Get("Content-Type"))

	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, h.upstreamURL, bytes.NewReader(body))
	if err != nil {
		logger.Errorf("token relay: failed to build upstream request for client_id=%s: %v", clientID, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", r.Header.Get("Content-Type"))

	start := time.Now()
	resp, err := h.httpClient.Do(req)
	if err != nil {
		logger.Errorf("token relay: upstream request failed for client_id=%s: %v", clientID, err)
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	if err != nil {
		logger.Errorf("token relay: failed to read upstream response for client_id=%s: %v", clientID, err)
		http.Error(w, "failed to read upstream response", http.StatusBadGateway)
		return
	}

	var expiresIn int
	if resp.StatusCode == http.StatusOK {
		var tokenResp tokenResponse
		if err := json.Unmarshal(respBody, &tokenResp); err == nil {
			expiresIn = tokenResp.ExpiresIn
		}
	}

	logger.Printf("token relay: client_id=%s status=%d expires_in=%ds duration=%s",
		clientID, resp.StatusCode, expiresIn, time.Since(start).Round(time.Millisecond))

	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
}

// extractClientID parses client_id from an application/x-www-form-urlencoded
// or JSON request body without consuming the reader.
func extractClientID(body []byte, contentType string) string {
	if strings.Contains(contentType, "application/x-www-form-urlencoded") || contentType == "" {
		values, err := url.ParseQuery(string(body))
		if err != nil {
			return ""
		}
		return values.Get("client_id")
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return ""
	}
	if v, ok := m["client_id"].(string); ok {
		return v
	}
	return ""
}
