package main

import (
	"path/filepath"
	"testing"
)

func TestTimelinePersistsAlertTransitions(t *testing.T) {
	store, err := newEventStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	current := metrics{CPUReady: true, CPUPercent: 91}
	if err := store.evaluate(current); err != nil {
		t.Fatal(err)
	}
	if err := store.evaluate(current); err != nil {
		t.Fatal(err)
	}
	if got := len(store.list("CPU", 10)); got != 1 {
		t.Fatalf("CPU alert count = %d, want 1", got)
	}

	reloaded, err := newEventStore(filepath.Dir(store.path))
	if err != nil {
		t.Fatal(err)
	}
	if err := reloaded.evaluate(current); err != nil {
		t.Fatal(err)
	}
	if got := len(reloaded.list("", 10)); got != 1 {
		t.Fatalf("event count after reload = %d, want 1", got)
	}

	current.CPUPercent = 40
	if err := reloaded.evaluate(current); err != nil {
		t.Fatal(err)
	}
	events := reloaded.list("CPU", 10)
	if len(events) != 2 || events[0].Active || events[0].Severity != "info" || !events[1].Active {
		t.Fatalf("unexpected alert transitions: %+v", events)
	}
}

func TestTimelineMemoryAndStorageThresholds(t *testing.T) {
	store, err := newEventStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	current := metrics{
		Memory:      memoryMetric{TotalBytes: 100, UsedBytes: 96},
		Filesystems: []filesystemMetric{{Mount: "/", UsagePercent: 86}},
	}
	if err := store.evaluate(current); err != nil {
		t.Fatal(err)
	}
	if got := len(store.list("Memory", 10)); got != 1 {
		t.Fatalf("memory alert count = %d, want 1", got)
	}
	if got := len(store.list("Storage", 10)); got != 1 {
		t.Fatalf("storage alert count = %d, want 1", got)
	}
	if got := store.list("CPU", 10); len(got) != 0 {
		t.Fatalf("category filter returned unrelated events: %+v", got)
	}
}

func TestTimelineEscalatesMemoryAlert(t *testing.T) {
	store, err := newEventStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	current := metrics{Memory: memoryMetric{TotalBytes: 100, UsedBytes: 92}}
	if err := store.evaluate(current); err != nil {
		t.Fatal(err)
	}
	current.Memory.UsedBytes = 97
	if err := store.evaluate(current); err != nil {
		t.Fatal(err)
	}
	events := store.list("Memory", 10)
	if len(events) != 2 || events[0].Severity != "critical" || events[1].Severity != "warning" {
		t.Fatalf("expected warning then critical escalation, got %+v", events)
	}
}
