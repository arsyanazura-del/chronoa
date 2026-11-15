package main

import (
	"bufio"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type metrics struct {
	Hostname       string             `json:"hostname"`
	SampledAt      string             `json:"sampledAt"`
	UptimeSeconds  float64            `json:"uptimeSeconds"`
	LoadAverage    [3]float64         `json:"loadAverage"`
	ProcessCount   int                `json:"processCount"`
	CPUPercent     float64            `json:"cpuPercent"`
	CPUReady       bool               `json:"cpuReady"`
	Cores          []coreMetric       `json:"cores"`
	Memory         memoryMetric       `json:"memory"`
	Filesystems    []filesystemMetric `json:"filesystems"`
	Interfaces     []networkMetric    `json:"interfaces"`
	RXBytesPerSec  float64            `json:"rxBytesPerSec"`
	TXBytesPerSec  float64            `json:"txBytesPerSec"`
	TCPConnections int                `json:"tcpConnections"`
	TemperatureC   *float64           `json:"temperatureC"`
}

type coreMetric struct {
	Name    string  `json:"name"`
	Percent float64 `json:"percent"`
}

type memoryMetric struct {
	TotalBytes     uint64 `json:"totalBytes"`
	UsedBytes      uint64 `json:"usedBytes"`
	AvailableBytes uint64 `json:"availableBytes"`
	CachedBytes    uint64 `json:"cachedBytes"`
	BufferBytes    uint64 `json:"bufferBytes"`
	SwapTotalBytes uint64 `json:"swapTotalBytes"`
	SwapUsedBytes  uint64 `json:"swapUsedBytes"`
}

type filesystemMetric struct {
	Mount        string  `json:"mount"`
	Device       string  `json:"device"`
	Filesystem   string  `json:"filesystem"`
	TotalBytes   uint64  `json:"totalBytes"`
	UsedBytes    uint64  `json:"usedBytes"`
	UsagePercent float64 `json:"usagePercent"`
}

type networkMetric struct {
	Name          string  `json:"name"`
	Status        string  `json:"status"`
	Address       string  `json:"address"`
	RXBytes       uint64  `json:"rxBytes"`
	TXBytes       uint64  `json:"txBytes"`
	Errors        uint64  `json:"errors"`
	Drops         uint64  `json:"drops"`
	RXBytesPerSec float64 `json:"rxBytesPerSec"`
	TXBytesPerSec float64 `json:"txBytesPerSec"`
}

type cpuTimes struct {
	total uint64
	idle  uint64
}

type networkTotals struct {
	rx uint64
	tx uint64
}

type sampler struct {
	mu       sync.Mutex
	previous map[string]cpuTimes
	network  map[string]networkTotals
	sampled  time.Time
}

func (s *sampler) collect() (metrics, error) {
	result := metrics{SampledAt: time.Now().Format("15:04:05 -0700 MST")}
	result.Hostname, _ = os.Hostname()
	result.UptimeSeconds, _ = readUptime()
	result.LoadAverage, _ = readLoadAverage()
	result.ProcessCount, _ = countProcesses()
	result.Memory = readMemory()
	result.Filesystems = readFilesystems()
	result.TemperatureC = readTemperature()
	result.TCPConnections = countTCPConnections()

	s.mu.Lock()
	currentCPU, err := readCPUTimes()
	if err != nil {
		s.mu.Unlock()
		return metrics{}, err
	}
	currentNetwork := readNetworkCounters()
	now := time.Now()
	result.CPUReady = len(s.previous) > 0
	result.CPUPercent, result.Cores = cpuUsage(s.previous, currentCPU)
	elapsed := now.Sub(s.sampled).Seconds()
	result.Interfaces, result.RXBytesPerSec, result.TXBytesPerSec = readInterfaces(s.network, currentNetwork, elapsed)
	s.previous = currentCPU
	s.network = currentNetwork
	s.sampled = now
	s.mu.Unlock()
	return result, nil
}

func readCPUTimes() (map[string]cpuTimes, error) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	result := make(map[string]cpuTimes)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 || (fields[0] != "cpu" && !strings.HasPrefix(fields[0], "cpu")) {
			break
		}
		var total, idle uint64
		for i, field := range fields[1:] {
			value, parseErr := strconv.ParseUint(field, 10, 64)
			if parseErr != nil {
				continue
			}
			total += value
			if i == 3 || i == 4 {
				idle += value
			}
		}
		result[fields[0]] = cpuTimes{total: total, idle: idle}
	}
	return result, scanner.Err()
}

func cpuUsage(previous, current map[string]cpuTimes) (float64, []coreMetric) {
	percentage := func(name string) float64 {
		before, ok := previous[name]
		after := current[name]
		if !ok || after.total <= before.total {
			return 0
		}
		total := after.total - before.total
		idle := after.idle - before.idle
		if idle >= total {
			return 0
		}
		return float64(total-idle) * 100 / float64(total)
	}

	cores := make([]coreMetric, 0, len(current))
	for name := range current {
		if name != "cpu" {
			cores = append(cores, coreMetric{Name: name, Percent: percentage(name)})
		}
	}
	sort.Slice(cores, func(i, j int) bool {
		left, _ := strconv.Atoi(strings.TrimPrefix(cores[i].Name, "cpu"))
		right, _ := strconv.Atoi(strings.TrimPrefix(cores[j].Name, "cpu"))
		return left < right
	})
	return percentage("cpu"), cores
}

func readMemory() memoryMetric {
	values := make(map[string]uint64)
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return memoryMetric{}
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		value, parseErr := strconv.ParseUint(fields[1], 10, 64)
		if parseErr == nil {
			values[strings.TrimSuffix(fields[0], ":")] = value * 1024
		}
	}
	available := values["MemAvailable"]
	if available == 0 {
		available = values["MemFree"]
	}
	total := values["MemTotal"]
	used := total - min(total, available)
	return memoryMetric{
		TotalBytes: total, UsedBytes: used, AvailableBytes: available,
		CachedBytes: values["Cached"] + values["SReclaimable"], BufferBytes: values["Buffers"],
		SwapTotalBytes: values["SwapTotal"], SwapUsedBytes: values["SwapTotal"] - min(values["SwapTotal"], values["SwapFree"]),
	}
}

func readFilesystems() []filesystemMetric {
	file, err := os.Open("/proc/mounts")
	if err != nil {
		return nil
	}
	defer file.Close()
	ignored := map[string]bool{"proc": true, "sysfs": true, "devtmpfs": true, "devpts": true, "tmpfs": true, "cgroup": true, "cgroup2": true, "securityfs": true, "debugfs": true, "tracefs": true, "pstore": true, "mqueue": true, "hugetlbfs": true, "configfs": true, "overlay": true, "fusectl": true, "squashfs": true}
	decode := strings.NewReplacer("\\040", " ", "\\011", "\t", "\\134", "\\")
	seen := make(map[string]int)
	var result []filesystemMetric
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 || ignored[fields[2]] {
			continue
		}
		mount := decode.Replace(fields[1])
		if info, statErr := os.Stat(mount); statErr != nil || !info.IsDir() {
			continue
		}
		var stats syscall.Statfs_t
		if syscall.Statfs(mount, &stats) != nil {
			continue
		}
		total := stats.Blocks * uint64(stats.Bsize)
		available := stats.Bavail * uint64(stats.Bsize)
		used := total - min(total, available)
		percent := 0.0
		if total > 0 {
			percent = float64(used) * 100 / float64(total)
		}
		device := decode.Replace(fields[0])
		key := device + "\x00" + fields[2]
		entry := filesystemMetric{Mount: mount, Device: device, Filesystem: fields[2], TotalBytes: total, UsedBytes: used, UsagePercent: percent}
		if index, exists := seen[key]; exists {
			if mountDepth(mount) < mountDepth(result[index].Mount) {
				result[index] = entry
			}
			continue
		}
		seen[key] = len(result)
		result = append(result, entry)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Mount < result[j].Mount })
	return result
}

func readNetworkCounters() map[string]networkTotals {
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		return nil
	}
	defer file.Close()
	result := make(map[string]networkTotals)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		name := strings.TrimSpace(parts[0])
		fields := strings.Fields(parts[1])
		if name == "lo" || len(fields) < 16 {
			continue
		}
		rx, rxErr := strconv.ParseUint(fields[0], 10, 64)
		tx, txErr := strconv.ParseUint(fields[8], 10, 64)
		if rxErr == nil && txErr == nil {
			result[name] = networkTotals{rx: rx, tx: tx}
		}
	}
	return result
}

func readInterfaces(previous, current map[string]networkTotals, elapsed float64) ([]networkMetric, float64, float64) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, 0, 0
	}
	var result []networkMetric
	var rxTotal, txTotal float64
	for _, iface := range interfaces {
		if iface.Name == "lo" {
			continue
		}
		counters, ok := current[iface.Name]
		if !ok {
			continue
		}
		var rxRate, txRate float64
		if before, exists := previous[iface.Name]; exists && elapsed > 0 {
			if counters.rx >= before.rx {
				rxRate = float64(counters.rx-before.rx) / elapsed
			}
			if counters.tx >= before.tx {
				txRate = float64(counters.tx-before.tx) / elapsed
			}
		}
		status := "unknown"
		if data, readErr := os.ReadFile(filepath.Join("/sys/class/net", iface.Name, "operstate")); readErr == nil {
			status = strings.TrimSpace(string(data))
		}
		address := ""
		if addresses, addrErr := iface.Addrs(); addrErr == nil {
			for _, candidate := range addresses {
				ip, _, parseErr := net.ParseCIDR(candidate.String())
				if parseErr == nil && ip.To4() != nil {
					address = ip.String()
					break
				}
			}
		}
		var rxErrors, txErrors, rxDrops, txDrops uint64
		if data, readErr := os.ReadFile(filepath.Join("/sys/class/net", iface.Name, "statistics", "rx_errors")); readErr == nil {
			rxErrors, _ = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		}
		if data, readErr := os.ReadFile(filepath.Join("/sys/class/net", iface.Name, "statistics", "tx_errors")); readErr == nil {
			txErrors, _ = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		}
		if data, readErr := os.ReadFile(filepath.Join("/sys/class/net", iface.Name, "statistics", "rx_dropped")); readErr == nil {
			rxDrops, _ = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		}
		if data, readErr := os.ReadFile(filepath.Join("/sys/class/net", iface.Name, "statistics", "tx_dropped")); readErr == nil {
			txDrops, _ = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		}
		result = append(result, networkMetric{Name: iface.Name, Status: status, Address: address, RXBytes: counters.rx, TXBytes: counters.tx, Errors: rxErrors + txErrors, Drops: rxDrops + txDrops, RXBytesPerSec: rxRate, TXBytesPerSec: txRate})
		rxTotal += rxRate
		txTotal += txRate
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, rxTotal, txTotal
}

func readUptime() (float64, error) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0, errors.New("empty uptime")
	}
	return strconv.ParseFloat(fields[0], 64)
}

func readLoadAverage() ([3]float64, error) {
	var result [3]float64
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return result, err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return result, errors.New("invalid load average")
	}
	for i := range result {
		result[i], err = strconv.ParseFloat(fields[i], 64)
		if err != nil {
			return [3]float64{}, err
		}
	}
	return result, nil
}

func countProcesses() (int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}
	count := 0
	for _, entry := range entries {
		if entry.IsDir() {
			if _, err := strconv.Atoi(entry.Name()); err == nil {
				count++
			}
		}
	}
	return count, nil
}

func readTemperature() *float64 {
	paths, _ := filepath.Glob("/sys/class/thermal/thermal_zone*/temp")
	for _, path := range paths {
		zoneType, err := os.ReadFile(filepath.Join(filepath.Dir(path), "type"))
		if err != nil || !isCPUSensor(string(zoneType)) {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		value, err := strconv.ParseFloat(strings.TrimSpace(string(data)), 64)
		if err != nil {
			continue
		}
		if value > 1000 {
			value /= 1000
		}
		if value >= 0 && value <= 150 {
			return &value
		}
	}
	paths, _ = filepath.Glob("/sys/class/hwmon/hwmon*/temp*_input")
	for _, path := range paths {
		label, err := os.ReadFile(strings.TrimSuffix(path, "_input") + "_label")
		if err != nil || !isCPUSensor(string(label)) {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		value, err := strconv.ParseFloat(strings.TrimSpace(string(data)), 64)
		if err != nil {
			continue
		}
		value /= 1000
		if value >= 0 && value <= 150 {
			return &value
		}
	}
	return nil
}

func isCPUSensor(label string) bool {
	label = strings.ToLower(strings.TrimSpace(label))
	return strings.Contains(label, "cpu") || strings.Contains(label, "package") || strings.Contains(label, "coretemp") || strings.Contains(label, "processor")
}

func mountDepth(path string) int {
	return strings.Count(filepath.Clean(path), string(os.PathSeparator))
}

func countTCPConnections() int {
	count := 0
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) > 3 && fields[3] == "01" {
				count++
			}
		}
		file.Close()
	}
	return count
}
