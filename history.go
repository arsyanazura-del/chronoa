package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	historyRetention  = 30 * 24 * time.Hour
	maxHistoryPoints  = 4000
	historyFilePrefix = "metrics-"
)

var historyWindows = map[string]time.Duration{
	"1m":  time.Minute,
	"5m":  5 * time.Minute,
	"1h":  time.Hour,
	"24h": 24 * time.Hour,
	"30d": historyRetention,
}

type metricPoint struct {
	Timestamp     time.Time `json:"timestamp"`
	CPUReady      bool      `json:"cpuReady"`
	CPUPercent    float64   `json:"cpuPercent"`
	MemoryUsed    uint64    `json:"memoryUsedBytes"`
	MemoryTotal   uint64    `json:"memoryTotalBytes"`
	RXBytesPerSec float64   `json:"rxBytesPerSec"`
	TXBytesPerSec float64   `json:"txBytesPerSec"`
	TemperatureC  *float64  `json:"temperatureC"`
}

type historyStore struct {
	mu           sync.RWMutex
	directory    string
	lastPrunedOn string
}

func newHistoryStore(directory string) (*historyStore, error) {
	if err := os.MkdirAll(directory, 0750); err != nil {
		return nil, err
	}
	return &historyStore{directory: directory}, nil
}

func (s *historyStore) append(current metrics) error {
	now := time.Now().UTC()
	point := metricPoint{
		Timestamp: now, CPUReady: current.CPUReady, CPUPercent: current.CPUPercent,
		MemoryUsed: current.Memory.UsedBytes, MemoryTotal: current.Memory.TotalBytes,
		RXBytesPerSec: current.RXBytesPerSec, TXBytesPerSec: current.TXBytesPerSec,
		TemperatureC: current.TemperatureC,
	}
	data, err := json.Marshal(point)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	path := filepath.Join(s.directory, historyFilePrefix+now.Format("2006-01-02")+".jsonl")
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err := file.Write(append(data, '\n')); err != nil {
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
	day := now.Format("2006-01-02")
	if day != s.lastPrunedOn {
		if err := s.pruneLocked(now); err != nil {
			return err
		}
		s.lastPrunedOn = day
	}
	return nil
}

func (s *historyStore) query(window time.Duration) ([]metricPoint, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	files, err := filepath.Glob(filepath.Join(s.directory, historyFilePrefix+"*.jsonl"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	cutoff := time.Now().UTC().Add(-window)
	points := make([]metricPoint, 0)
	for _, path := range files {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 4096), 1024*1024)
		for scanner.Scan() {
			var point metricPoint
			if json.Unmarshal(scanner.Bytes(), &point) != nil || point.Timestamp.Before(cutoff) {
				continue
			}
			points = append(points, point)
		}
		scanErr := scanner.Err()
		closeErr := file.Close()
		if scanErr != nil {
			return nil, scanErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
	}
	if len(points) > maxHistoryPoints {
		points = downsample(points, maxHistoryPoints)
	}
	return points, nil
}

func (s *historyStore) pruneLocked(now time.Time) error {
	entries, err := os.ReadDir(s.directory)
	if err != nil {
		return err
	}
	cutoffDay := now.Add(-historyRetention).Format("2006-01-02")
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, historyFilePrefix) || !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		day := strings.TrimSuffix(strings.TrimPrefix(name, historyFilePrefix), ".jsonl")
		if _, err := time.Parse("2006-01-02", day); err != nil {
			continue
		}
		if day < cutoffDay {
			if err := os.Remove(filepath.Join(s.directory, name)); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove expired history %s: %w", name, err)
			}
		}
	}
	return nil
}

func downsample(points []metricPoint, limit int) []metricPoint {
	if limit <= 0 {
		return []metricPoint{}
	}
	if len(points) <= limit {
		return points
	}
	if limit == 1 {
		return []metricPoint{points[len(points)-1]}
	}
	result := make([]metricPoint, 0, limit)
	for i := 0; i < limit; i++ {
		index := i * (len(points) - 1) / (limit - 1)
		result = append(result, points[index])
	}
	return result
}
