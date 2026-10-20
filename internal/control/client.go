package control

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

const maxControlResponse = 1 << 20

type Client struct {
	BaseURL, NodeID, Secret, Version string
	FallbackURLs                     []string
	HTTP                             *http.Client
	mu                               sync.Mutex
	activeURL                        int
}

func (c *Client) request(ctx context.Context, method, path string, input, output any) error {
	var body []byte
	var err error
	if input != nil {
		body, err = json.Marshal(input)
		if err != nil {
			return err
		}
	}
	baseURL, err := c.currentBaseURL()
	if err != nil {
		return err
	}
	u, err := url.JoinPath(baseURL, path)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	nonceBytes := make([]byte, 24)
	if _, err := rand.Read(nonceBytes); err != nil {
		return err
	}
	nonce := hex.EncodeToString(nonceBytes)
	canonical := strings.Join([]string{method, req.URL.RequestURI(), c.NodeID, ts, nonce}, "\n") + "\n"
	mac := hmac.New(sha256.New, []byte(c.Secret))
	mac.Write(append([]byte(canonical), body...))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Node-Id", c.NodeID)
	req.Header.Set("X-Signature-Version", "2")
	req.Header.Set("X-Signature-Timestamp", ts)
	req.Header.Set("X-Signature-Nonce", nonce)
	req.Header.Set("X-Signature-V2", hex.EncodeToString(mac.Sum(nil)))
	client := secureHTTPClient(c.HTTP)
	resp, err := client.Do(req)
	if err != nil {
		c.advanceBaseURL()
		return fmt.Errorf("control request via %s: %w", baseURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		if resp.StatusCode >= 500 {
			c.advanceBaseURL()
		}
		return fmt.Errorf("control HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if output != nil {
		return decodeResponse(resp.Body, output)
	}
	return nil
}

func ParseFallbackURLs(raw string) ([]string, error) {
	items := make([]string, 0)
	seen := make(map[string]struct{})
	for _, value := range strings.Split(raw, ",") {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		validated, err := validateBaseURL(value)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[validated]; exists {
			continue
		}
		seen[validated] = struct{}{}
		items = append(items, validated)
	}
	return items, nil
}

func (c *Client) currentBaseURL() (string, error) {
	urls := append([]string{c.BaseURL}, c.FallbackURLs...)
	c.mu.Lock()
	index := c.activeURL % len(urls)
	c.mu.Unlock()
	return validateBaseURL(urls[index])
}

func (c *Client) advanceBaseURL() {
	count := 1 + len(c.FallbackURLs)
	if count < 2 {
		return
	}
	c.mu.Lock()
	c.activeURL = (c.activeURL + 1) % count
	c.mu.Unlock()
}

func (c *Client) Heartbeat(ctx context.Context, port int) error {
	return c.request(ctx, http.MethodPost, "/api/v1/nodes/heartbeat", map[string]any{"version": c.Version, "listen_port": port}, nil)
}

func (c *Client) Observations(ctx context.Context, items any) error {
	return c.request(ctx, http.MethodPost, "/api/v1/nodes/observations", map[string]any{"observations": items}, nil)
}

func Enroll(ctx context.Context, baseURL, token string, port int) (nodeID, secret string, err error) {
	var out struct {
		NodeID     string `json:"node_id"`
		NodeSecret string `json:"node_secret"`
	}
	if _, err = validateBaseURL(baseURL); err != nil {
		return "", "", err
	}
	c := &Client{BaseURL: baseURL, HTTP: secureHTTPClient(nil)}
	err = c.requestUnsigned(ctx, "/api/v1/nodes/enroll", map[string]any{"token": token, "listen_port": port}, &out)
	return out.NodeID, out.NodeSecret, err
}

func (c *Client) requestUnsigned(ctx context.Context, path string, input, output any) error {
	body, _ := json.Marshal(input)
	baseURL, err := validateBaseURL(c.BaseURL)
	if err != nil {
		return err
	}
	u, err := url.JoinPath(baseURL, path)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := secureHTTPClient(c.HTTP).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("enrollment HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return decodeResponse(resp.Body, output)
}

func validateBaseURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !u.IsAbs() || u.Host == "" {
		return "", fmt.Errorf("invalid control URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("control URL must not contain credentials, query, or fragment")
	}
	if u.Scheme != "https" {
		host := u.Hostname()
		addr, addrErr := netip.ParseAddr(host)
		loopback := strings.EqualFold(host, "localhost") || (addrErr == nil && addr.IsLoopback())
		if u.Scheme != "http" || !loopback {
			return "", fmt.Errorf("control URL must use HTTPS (HTTP is allowed only for loopback development)")
		}
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func secureHTTPClient(base *http.Client) *http.Client {
	client := http.Client{Timeout: 15 * time.Second}
	if base != nil {
		client = *base
		if client.Timeout == 0 {
			client.Timeout = 15 * time.Second
		}
	}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &client
}

func decodeResponse(body io.Reader, output any) error {
	payload, err := io.ReadAll(io.LimitReader(body, maxControlResponse+1))
	if err != nil {
		return err
	}
	if len(payload) > maxControlResponse {
		return fmt.Errorf("control response exceeds %d bytes", maxControlResponse)
	}
	return json.Unmarshal(payload, output)
}
