package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const maxEvents = 500

type systemEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Category  string    `json:"category"`
	Severity  string    `json:"severity"`
	Message   string    `json:"message"`
	Active    bool      `json:"active"`
}

type eventState struct {
	Events []systemEvent     `json:"events"`
	Active map[string]string `json:"active"`
}

type eventStore struct {
	mu     sync.RWMutex
	path   string
	events []systemEvent
	active map[string]string
}

func newEventStore(directory string) (*eventStore, error) {
	if err := os.MkdirAll(directory, 0750); err != nil {
		return nil, err
	}
	store := &eventStore{
		path:   filepath.Join(directory, "events.json"),
		events: []systemEvent{},
		active: make(map[string]string),
	}
	data, err := os.ReadFile(store.path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err == nil {
		var state eventState
		if err := json.Unmarshal(data, &state); err != nil {
			return nil, fmt.Errorf("decode timeline state: %w", err)
		}
		store.events = state.Events
		if store.events == nil {
			store.events = []systemEvent{}
		}
		if len(store.events) > maxEvents {
			store.events = store.events[len(store.events)-maxEvents:]
		}
		if state.Active != nil {
			store.active = state.Active
		}
	}
	return store, nil
}

func (s *eventStore) evaluate(current metrics) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	nextActive := make(map[string]string, len(s.active))
	for key, value := range s.active {
		nextActive[key] = value
	}
	nextEvents := append([]systemEvent(nil), s.events...)
	changed := false
	transition := func(key, category, message string, triggered bool, severity string) {
		previousSeverity := nextActive[key]
		if triggered && previousSeverity == severity {
			return
		}
		if !triggered && previousSeverity == "" {
			return
		}
		if triggered {
			nextActive[key] = severity
		} else {
			delete(nextActive, key)
			severity = "info"
		}
		nextEvents = append(nextEvents, systemEvent{
			Timestamp: time.Now().UTC(),
			Category:  category,
			Severity:  severity,
			Message:   message,
			Active:    triggered,
		})
		changed = true
	}

	if current.CPUReady {
		triggered := current.CPUPercent >= 85
		message := fmt.Sprintf("CPU usage returned to %.1f%%", current.CPUPercent)
		severity := "warning"
		if triggered {
			message = fmt.Sprintf("CPU usage reached %.1f%% (limit 85%%)", current.CPUPercent)
		}
		transition("cpu", "CPU", message, triggered, severity)
	}
	if current.Memory.TotalBytes > 0 {
		percent := float64(current.Memory.UsedBytes) * 100 / float64(current.Memory.TotalBytes)
		triggered := percent >= 90
		message := fmt.Sprintf("Memory usage returned to %.1f%%", percent)
		severity := "warning"
		if triggered {
			message = fmt.Sprintf("Memory usage reached %.1f%% (limit 90%%)", percent)
			if percent >= 95 {
				severity = "critical"
			}
		}
		transition("memory", "Memory", message, triggered, severity)
	}
	for _, filesystem := range current.Filesystems {
		triggered := filesystem.UsagePercent >= 85
		message := fmt.Sprintf("Storage %s returned to %.1f%%", filesystem.Mount, filesystem.UsagePercent)
		if triggered {
			message = fmt.Sprintf("Storage %s reached %.1f%% (limit 85%%)", filesystem.Mount, filesystem.UsagePercent)
		}
		transition("storage:"+filesystem.Mount, "Storage", message, triggered, "warning")
	}
	if current.TemperatureC != nil {
		triggered := *current.TemperatureC >= 80
		message := fmt.Sprintf("CPU temperature returned to %.1f C", *current.TemperatureC)
		if triggered {
			message = fmt.Sprintf("CPU temperature reached %.1f C (limit 80 C)", *current.TemperatureC)
		}
		transition("temperature", "Temperature", message, triggered, "warning")
	}
	if !changed {
		return nil
	}
	if len(nextEvents) > maxEvents {
		nextEvents = nextEvents[len(nextEvents)-maxEvents:]
	}
	previousEvents, previousActive := s.events, s.active
	s.events, s.active = nextEvents, nextActive
	if err := s.saveLocked(); err != nil {
		s.events, s.active = previousEvents, previousActive
		return err
	}
	return nil
}

func (s *eventStore) list(category string, limit int) []systemEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]systemEvent, 0, min(limit, len(s.events)))
	for i := len(s.events) - 1; i >= 0 && len(result) < limit; i-- {
		if category != "" && !strings.EqualFold(category, s.events[i].Category) {
			continue
		}
		result = append(result, s.events[i])
	}
	return result
}

func (s *eventStore) saveLocked() error {
	data, err := json.Marshal(eventState{Events: s.events, Active: s.active})
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(s.path), ".events-*.tmp")
	if err != nil {
		return err
	}
	tempPath := file.Name()
	defer os.Remove(tempPath)
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, s.path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(s.path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
