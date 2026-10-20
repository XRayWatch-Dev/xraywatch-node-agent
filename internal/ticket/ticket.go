package ticket

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

type Probe struct {
	RunID         string    `json:"run_id"`
	NodeID        string    `json:"node_id"`
	EndpointID    string    `json:"endpoint_id"`
	Protocol      string    `json:"protocol"`
	PayloadBudget int       `json:"payload_budget"`
	ExpiresAt     time.Time `json:"expires_at"`
	Nonce         string    `json:"nonce"`
	Signature     string    `json:"signature,omitempty"`
}

func (p Probe) canonical() ([]byte, error) { p.Signature = ""; return json.Marshal(p) }

type Verifier struct {
	Key    ed25519.PublicKey
	NodeID string
	mu     sync.Mutex
	seen   map[string]time.Time
	Now    func() time.Time
}

func New(key, nodeID string) (*Verifier, error) {
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("invalid Ed25519 trust key")
	}
	return &Verifier{Key: ed25519.PublicKey(raw), NodeID: nodeID, seen: map[string]time.Time{}, Now: time.Now}, nil
}
func (v *Verifier) Verify(raw []byte, protocol string, size int) (Probe, error) {
	var p Probe
	if len(raw) > 4096 || json.Unmarshal(raw, &p) != nil {
		return p, errors.New("invalid probe ticket")
	}
	now := v.Now().UTC()
	if p.NodeID != v.NodeID || p.EndpointID == "" || p.Protocol != protocol || p.RunID == "" || len(p.Nonce) < 16 || !p.ExpiresAt.After(now) || p.ExpiresAt.After(now.Add(2*time.Minute)) || p.PayloadBudget < 1 || p.PayloadBudget > 256<<10 || size > p.PayloadBudget {
		return p, errors.New("probe ticket scope rejected")
	}
	sig, err := base64.StdEncoding.DecodeString(p.Signature)
	if err != nil {
		return p, errors.New("invalid signature")
	}
	canonical, _ := p.canonical()
	if !ed25519.Verify(v.Key, canonical, sig) {
		return p, errors.New("invalid signature")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	for n, e := range v.seen {
		if !e.After(now) {
			delete(v.seen, n)
		}
	}
	if _, ok := v.seen[p.Nonce]; ok {
		return p, errors.New("probe ticket replayed")
	}
	if len(v.seen) >= 1024 {
		return p, errors.New("probe replay cache full")
	}
	v.seen[p.Nonce] = p.ExpiresAt
	return p, nil
}
func Sign(private ed25519.PrivateKey, p Probe) ([]byte, error) {
	canonical, err := p.canonical()
	if err != nil {
		return nil, err
	}
	p.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, canonical))
	return json.Marshal(p)
}
