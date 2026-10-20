package control

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidateBaseURL(t *testing.T) {
	for _, valid := range []string{"https://control.example.com", "http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080"} {
		if _, err := validateBaseURL(valid); err != nil {
			t.Errorf("validateBaseURL(%q): %v", valid, err)
		}
	}
	for _, invalid := range []string{"http://control.example.com", "ftp://control.example.com", "//control.example.com", "https://user:pass@control.example.com", "https://control.example.com?q=secret", "https://control.example.com/#fragment"} {
		if _, err := validateBaseURL(invalid); err == nil {
			t.Errorf("validateBaseURL(%q) unexpectedly succeeded", invalid)
		}
	}
}

func TestEnrollRejectsRedirect(t *testing.T) {
	destinationCalled := false
	destination := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		destinationCalled = true
	}))
	defer destination.Close()

	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()

	client := redirect.Client()
	c := &Client{BaseURL: redirect.URL, HTTP: client}
	var output map[string]any
	err := c.requestUnsigned(context.Background(), "/enroll", map[string]string{"token": "secret"}, &output)
	if err == nil || !strings.Contains(err.Error(), "307") {
		t.Fatalf("requestUnsigned redirect error=%v", err)
	}
	if destinationCalled {
		t.Fatal("secret-bearing request followed redirect")
	}
}

func TestRequestRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"value":"` + strings.Repeat("x", maxControlResponse) + `"}`))
	}))
	defer server.Close()
	c := &Client{BaseURL: server.URL, NodeID: "node", Secret: "secret", HTTP: server.Client()}
	var output map[string]any
	if err := c.request(context.Background(), http.MethodPost, "/test", nil, &output); err == nil {
		t.Fatal("oversized control response unexpectedly accepted")
	}
}
