package state

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

const MaxOutboxEntries = 512

var outboxMu sync.Mutex

type Observation struct {
	RunID      string         `json:"run_id"`
	EndpointID string         `json:"endpoint_id"`
	ObservedAt string         `json:"observed_at"`
	Stages     map[string]any `json:"stages"`
}

func AppendObservation(dir string, item Observation) error {
	outboxMu.Lock()
	defer outboxMu.Unlock()
	if item.RunID == "" || item.EndpointID == "" || item.ObservedAt == "" {
		return errors.New("observation identity is incomplete")
	}
	items, _ := readObservations(dir)
	items = append(items, item)
	if len(items) > MaxOutboxEntries {
		items = items[len(items)-MaxOutboxEntries:]
	}
	return writeObservations(dir, items)
}

func ReadObservations(dir string) ([]Observation, error) {
	outboxMu.Lock()
	defer outboxMu.Unlock()
	return readObservations(dir)
}
func readObservations(dir string) ([]Observation, error) {
	f, err := os.Open(filepath.Join(dir, "observations.jsonl"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var items []Observation
	s := bufio.NewScanner(f)
	for s.Scan() {
		var item Observation
		if err := json.Unmarshal(s.Bytes(), &item); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, s.Err()
}

func AckObservations(dir string, count int) error {
	outboxMu.Lock()
	defer outboxMu.Unlock()
	items, err := readObservations(dir)
	if err != nil {
		return err
	}
	if count < 0 || count > len(items) {
		return errors.New("invalid acknowledgement")
	}
	return writeObservations(dir, items[count:])
}

func writeObservations(dir string, items []Observation) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	path := filepath.Join(dir, "observations.jsonl")
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	for _, item := range items {
		if err := enc.Encode(item); err != nil {
			f.Close()
			return err
		}
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
