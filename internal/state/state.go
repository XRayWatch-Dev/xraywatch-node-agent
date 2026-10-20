package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type Identity struct {
	NodeID string `json:"node_id"`
	Secret string `json:"secret"`
}

func Load(dir string) (Identity, error) {
	var value Identity
	b, err := os.ReadFile(filepath.Join(dir, "identity.json"))
	if err != nil {
		return value, err
	}
	if err := json.Unmarshal(b, &value); err != nil {
		return value, fmt.Errorf("decode identity: %w", err)
	}
	if value.NodeID == "" || value.Secret == "" {
		return value, errors.New("identity is incomplete")
	}
	return value, nil
}

func Save(dir string, value Identity) error {
	if value.NodeID == "" || value.Secret == "" {
		return errors.New("identity is incomplete")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, ".identity.json.tmp")
	if err := os.WriteFile(tmp, append(b, '\n'), 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, "identity.json")); err != nil {
		return err
	}
	return os.Chmod(filepath.Join(dir, "identity.json"), 0600)
}
