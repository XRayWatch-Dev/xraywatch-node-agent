package ticket

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"
)

func TestForgeryReplayAndBounds(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	v, _ := New(base64.StdEncoding.EncodeToString(pub), "node")
	now := time.Now().UTC()
	v.Now = func() time.Time { return now }
	raw, _ := Sign(priv, Probe{RunID: "run", NodeID: "node", EndpointID: "endpoint", Protocol: "tcp", PayloadBudget: 1024, ExpiresAt: now.Add(time.Minute), Nonce: "0123456789abcdef"})
	if _, err := v.Verify(raw, "tcp", 1024); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(raw, "tcp", 1024); err == nil {
		t.Fatal("replay accepted")
	}
	raw, _ = Sign(priv, Probe{RunID: "run", NodeID: "other", EndpointID: "endpoint", Protocol: "tcp", PayloadBudget: 1, ExpiresAt: now.Add(time.Minute), Nonce: "fedcba9876543210"})
	if _, err := v.Verify(raw, "tcp", 1); err == nil {
		t.Fatal("wrong node accepted")
	}
}
