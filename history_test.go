package main

import (
	"testing"
	"time"
)

func TestHistoryPersistsAndFiltersSamples(t *testing.T) {
	store, err := newHistoryStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.append(metrics{CPUReady: true, CPUPercent: 42, Memory: memoryMetric{UsedBytes: 60, TotalBytes: 100}}); err != nil {
		t.Fatal(err)
	}
	points, err := store.query(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(points) != 1 || points[0].CPUPercent != 42 || points[0].MemoryUsed != 60 {
		t.Fatalf("unexpected history points: %+v", points)
	}
}

func TestDownsampleKeepsLastPoint(t *testing.T) {
	points := make([]metricPoint, 8)
	for i := range points {
		points[i].Timestamp = time.Unix(int64(i), 0)
	}
	result := downsample(points, 4)
	if len(result) != 4 || result[len(result)-1].Timestamp != points[len(points)-1].Timestamp {
		t.Fatalf("downsample should be bounded and preserve newest point: %+v", result)
	}
}
