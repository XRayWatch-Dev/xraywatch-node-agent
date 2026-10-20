package state

import (
	"fmt"
	"os"
	"testing"
)

func TestIdentitySurvivesRecreate(t *testing.T) {
	dir := t.TempDir()
	want := Identity{NodeID: "node-1", Secret: "secret"}
	if err := Save(dir, want); err != nil {
		t.Fatal(err)
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %#v", got)
	}
	info, _ := os.Stat(dir + "/identity.json")
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
}

func TestOutboxIsBounded(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < MaxOutboxEntries+20; i++ {
		if err := AppendObservation(dir, Observation{RunID: fmt.Sprint(i), EndpointID: "e", ObservedAt: "now"}); err != nil {
			t.Fatal(err)
		}
	}
	items, err := ReadObservations(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != MaxOutboxEntries || items[0].RunID != "20" {
		t.Fatalf("unexpected bounded outbox: len=%d first=%s", len(items), items[0].RunID)
	}
}
