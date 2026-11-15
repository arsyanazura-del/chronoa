package main

import "testing"

func TestCPUUsage(t *testing.T) {
	previous := map[string]cpuTimes{
		"cpu":  {total: 100, idle: 60},
		"cpu0": {total: 50, idle: 25},
		"cpu1": {total: 50, idle: 35},
	}
	current := map[string]cpuTimes{
		"cpu":  {total: 200, idle: 120},
		"cpu0": {total: 100, idle: 45},
		"cpu1": {total: 100, idle: 75},
	}
	total, cores := cpuUsage(previous, current)
	if total != 40 {
		t.Fatalf("total CPU = %.1f, want 40", total)
	}
	if len(cores) != 2 || cores[0].Name != "cpu0" || cores[0].Percent != 60 || cores[1].Name != "cpu1" || cores[1].Percent != 20 {
		t.Fatalf("unexpected per-core metrics: %+v", cores)
	}
}

func TestCPUUsageWithoutBaseline(t *testing.T) {
	usage, cores := cpuUsage(nil, map[string]cpuTimes{"cpu": {total: 10, idle: 5}, "cpu0": {total: 10, idle: 5}})
	if usage != 0 || len(cores) != 1 || cores[0].Percent != 0 {
		t.Fatalf("first sample should be zero until a baseline exists: %.1f, %+v", usage, cores)
	}
}
