package collector

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"

	"ebpf_dpi/internal/labels"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// FlowRecord is the primary in-memory model for a network flow.
//
// It contains field names that map naturally to TCP/UDP flow metadata captured by eBPF.
// The dashboard reads these objects and renders them without persisting them anywhere.
// This intentionally keeps the runtime memory footprint small, which is appropriate for a
// local demo monitor.
type FlowRecord struct {
	ID         string    `json:"id"`
	SrcIP      string    `json:"src_ip"`
	DstIP      string    `json:"dst_ip"`
	SrcPort    uint16    `json:"src_port"`
	DstPort    uint16    `json:"dst_port"`
	Proto      string    `json:"proto"`
	BytesSent  uint64    `json:"bytes_sent"`
	BytesRecv  uint64    `json:"bytes_recv"`
	Retrans    uint32    `json:"retransmits"`
	Resets     uint32    `json:"resets"`
	DurationMs uint64    `json:"duration_ms"`
	PID        uint32    `json:"pid"`
	Process    string    `json:"process"`
	Container  string    `json:"container"`
	Namespace  string    `json:"namespace"`
	State      string    `json:"state"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Protocol   string    `json:"protocol"`
	Score      float64   `json:"score"`
}

// RuntimeStats is a top-level summary the UI can draw quickly.
//
// This is intentionally compact and contains only aggregate values, since the dashboard is
// meant to be lightweight and should not parse large internal state repeatedly.
type RuntimeStats struct {
	TotalFlows   int            `json:"total_flows"`
	BytesSent    uint64         `json:"bytes_sent"`
	BytesRecv    uint64         `json:"bytes_recv"`
	TopProto     string         `json:"top_proto"`
	PeakScore    float64        `json:"peak_score"`
	Alerts       []string       `json:"alerts"`
	TopProcesses []ProcessStat  `json:"top_processes"`
}

// ProcessStat summarizes the live traffic by process.
type ProcessStat struct {
	Process string `json:"process"`
	Bytes   uint64 `json:"bytes"`
	Flows   int    `json:"flows"`
}

// Collector is the central coordinator between kernel telemetry and the dashboard.
//
// It stores the live flow table in memory and exposes snapshot methods used by the UI.
// By design it does not persist any data beyond the current process lifetime.
type Collector struct {
	mu    sync.RWMutex
	flows map[string]*FlowRecord
	seed  int64
}

// bpfFlowEvent mirrors the structure produced by the BPF program.
//
// The field order matters because this is binary data read from the ring buffer.
// The layout must match the C struct in bpf/flow_monitor.bpf.c as closely as possible.
//
// The first fields are flow metadata, followed by traffic counters and then process metadata.
type bpfFlowEvent struct {
	Timestamp uint64
	SrcIP     uint32
	DstIP     uint32
	SrcPort   uint16
	DstPort   uint16
	Proto     uint8
	Pad       [3]byte
	BytesSent uint64
	BytesRecv uint64
	Retrans   uint32
	Resets    uint32
	PID       uint32
	Comm      [16]byte
}

// NewCollector creates a fresh in-memory collector.
func NewCollector() *Collector {
	return &Collector{
		flows: make(map[string]*FlowRecord),
		seed:  time.Now().UnixNano(),
	}
}

// Snapshot returns a list of the most recent flows ordered by last seen timestamp.
func (c *Collector) Snapshot() []FlowRecord {
	c.mu.RLock()
	defer c.mu.RUnlock()

	items := make([]FlowRecord, 0, len(c.flows))
	for _, flow := range c.flows {
		items = append(items, *flow)
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].LastSeen.After(items[j].LastSeen)
	})

	return items
}

// Stats returns summary metrics that the UI can render with minimal processing.
func (c *Collector) Stats() RuntimeStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := RuntimeStats{TotalFlows: len(c.flows)}
	protoCounts := map[string]int{}
	processCounts := map[string]*ProcessStat{}
	for _, flow := range c.flows {
		stats.BytesSent += flow.BytesSent
		stats.BytesRecv += flow.BytesRecv
		protoCounts[flow.Protocol]++
		if flow.Score > stats.PeakScore {
			stats.PeakScore = flow.Score
		}

		if process, ok := processCounts[flow.Process]; ok {
			process.Bytes += flow.BytesSent + flow.BytesRecv
			process.Flows++
		} else {
			processCounts[flow.Process] = &ProcessStat{Process: flow.Process, Bytes: flow.BytesSent + flow.BytesRecv, Flows: 1}
		}

		if flow.Retrans > 0 || flow.Resets > 0 || flow.Score > 80 {
			stats.Alerts = append(stats.Alerts, fmt.Sprintf("%s -> %s:%d has unusual traffic (score %.1f)", flow.Process, flow.DstIP, flow.DstPort, flow.Score))
		}
	}

	if len(protoCounts) > 0 {
		bestProto := ""
		bestCount := 0
		for proto, count := range protoCounts {
			if count > bestCount {
				bestCount = count
				bestProto = proto
			}
		}
		stats.TopProto = bestProto
	}

	for _, proc := range processCounts {
		stats.TopProcesses = append(stats.TopProcesses, *proc)
	}
	sort.Slice(stats.TopProcesses, func(i, j int) bool {
		return stats.TopProcesses[i].Bytes > stats.TopProcesses[j].Bytes
	})
	if len(stats.TopProcesses) > 5 {
		stats.TopProcesses = stats.TopProcesses[:5]
	}
	return stats
}

// StartBPF loads the compiled BPF object and then reads events from a ring buffer.
//
// This is the crucial bridging point between the kernel and the userspace collector.
// The function performs three important steps:
//   1. Load the compiled ELF object from disk.
//   2. Locate the ring buffer map created by the BPF code.
//   3. Read data from the ring buffer and translate it into in-memory flow objects.
func (c *Collector) StartBPF(objPath string) error {
	// We intentionally keep the runtime path strict and developer-friendly.
	// If the object is absent, return the error so the caller can decide whether to
	// fall back to demo mode or stop the application.
	if _, err := os.Stat(objPath); err != nil {
		return fmt.Errorf("BPF object %q not found: %w", objPath, err)
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("load BPF collection spec: %w", err)
	}

	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("create BPF collection: %w", err)
	}
	defer collection.Close()

	// A BPF ring buffer is a kernel-managed map designed for low-overhead event collection.
	// The eBPF program writes events to this map, and the userspace side reads them with
	// ringbuf.NewReader(). This is the preferred pattern for real-time observability.
	ringMap, ok := collection.Maps["flow_events"]
	if !ok {
		return fmt.Errorf("ring buffer map %q not found in BPF collection", "flow_events")
	}

	reader, err := ringbuf.NewReader(ringMap)
	if err != nil {
		return fmt.Errorf("create ring buffer reader: %w", err)
	}
	defer reader.Close()

	log.Printf("BPF monitor started: reading from %s", objPath)
	for {
		// ringbuf.Reader.Read() blocks until a record is available or the reader is closed.
		// Each record contains a byte slice that the BPF program sends out.
		record, err := reader.Read()
		if err != nil {
			return fmt.Errorf("read ring buffer record: %w", err)
		}
		c.processBPFRecord(record.RawSample)
	}
}

// processBPFRecord decodes a raw binary event from the kernel into a FlowRecord.
func (c *Collector) processBPFRecord(raw []byte) {
	if len(raw) < int(unsafeSizeOfBPFEvent()) {
		log.Printf("dropping short BPF event: got %d bytes", len(raw))
		return
	}

	// We decode the incoming byte stream using the same field layout we declared in C.
	// The Linux kernel writes binary data in little-endian format on x86_64, so we use
	// little-endian decoding here.
	var evt bpfFlowEvent
	buf := bytes.NewReader(raw)
	if err := binary.Read(buf, binary.LittleEndian, &evt); err != nil {
		log.Printf("binary decode of BPF event failed: %v", err)
		return
	}

	flow := c.flowFromEvent(evt)
	if flow == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.flows[flow.ID] = flow

	// Keep the in-memory data set bounded to the live dashboard window.
	// Because this is a local demo, we intentionally keep only a small slice of the newest data.
	if len(c.flows) > 200 {
		c.trimOldestFlows()
	}
}

// flowFromEvent converts a binary kernel event into a user-facing flow summary.
func (c *Collector) flowFromEvent(evt bpfFlowEvent) *FlowRecord {
	srcIP := ipv4ToString(evt.SrcIP)
	dstIP := ipv4ToString(evt.DstIP)
	if srcIP == "" || dstIP == "" {
		return nil
	}

	protocol := classifyProto(evt.Proto, evt.SrcPort, evt.DstPort)
	flowKey := fmt.Sprintf("%s:%d->%s:%d/%s", srcIP, evt.SrcPort, dstIP, evt.DstPort, protocol)

	processName := strings.TrimRight(string(evt.Comm[:]), "\x00")
	labelMeta := labels.GetProcessMetadata(evt.PID, processName)
	if labelMeta.Process == "" {
		labelMeta.Process = "unknown"
	}

	now := time.Now()
	flow := &FlowRecord{
		ID:        flowKey,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   evt.SrcPort,
		DstPort:   evt.DstPort,
		Proto:     mapProtoName(evt.Proto),
		BytesSent: evt.BytesSent,
		BytesRecv: evt.BytesRecv,
		Retrans:   evt.Retrans,
		Resets:    evt.Resets,
		PID:       evt.PID,
		Process:   labelMeta.Process,
		Container: labelMeta.Container,
		Namespace: labelMeta.Namespace,
		State:     "ESTABLISHED",
		FirstSeen: now,
		LastSeen:  now,
		Protocol:  protocol,
		Score:     scoreFlow(evt.BytesSent, evt.BytesRecv, evt.Retrans, evt.Resets),
	}
	return flow
}

// trimOldestFlows drops the oldest entries in memory to keep the UI responsive.
func (c *Collector) trimOldestFlows() {
	// A small, deterministic trim keeps the live view fast and easy to inspect.
	// There is no persistence layer in this project, so the memory ceiling is just a demo guard.
	entries := make([]string, 0, len(c.flows))
	for key := range c.flows {
		entries = append(entries, key)
	}

	sort.Slice(entries, func(i, j int) bool {
		return c.flows[entries[i]].LastSeen.Before(c.flows[entries[j]].LastSeen)
	})

	for i := 0; i < len(entries)/10; i++ {
		delete(c.flows, entries[i])
	}
}

// RunDemo generates synthetic traffic so the dashboard can be demonstrated even without a live kernel capture.
//
// This is useful in development and training and keeps the code accessible in environments
// where root or BPF access is unavailable. The generated flows mimic the patterns we aim to
// observe in real traffic: DNS, HTTP, MySQL, and active long-lived connections.
func (c *Collector) RunDemo() {
	// Use a fixed ticker so the demo remains deterministic and easy to understand in the UI.
	ticker := time.NewTicker(700 * time.Millisecond)
	defer ticker.Stop()

	// These traffic patterns emulate common network activity and are designed to exercise the
	// UI without requiring a running production service.
	for range ticker.C {
		c.mu.Lock()
		c.addDemoFlow("DNS", "10.0.0.5", "8.8.8.8", 52112, 53, 240, 180, 0, 0, 110)
		c.addDemoFlow("HTTP", "10.0.0.10", "172.16.0.42", 49152, 80, 1540, 3200, 1, 0, 250)
		c.addDemoFlow("MySQL", "10.0.0.12", "172.16.0.8", 47012, 3306, 2210, 4100, 0, 1, 340)
		c.addDemoFlow("gRPC", "10.0.0.18", "172.16.0.15", 50000, 50051, 3200, 2800, 0, 0, 410)
		c.mu.Unlock()
	}
}

// addDemoFlow inserts a synthetic flow into the in-memory store.
//
// The values are intentionally plausible but not tied to real world traffic. This keeps the
// dashboard visually interesting while preserving the broader monitoring design.
func (c *Collector) addDemoFlow(protocol, srcIP, dstIP string, srcPort, dstPort uint16, bytesSent, bytesRecv uint64, retrans, resets uint32, pid uint32) {
	now := time.Now()
	flowKey := fmt.Sprintf("%s:%d->%s:%d/%s", srcIP, srcPort, dstIP, dstPort, protocol)
	flow := &FlowRecord{
		ID:         flowKey,
		SrcIP:      srcIP,
		DstIP:      dstIP,
		SrcPort:    srcPort,
		DstPort:    dstPort,
		Proto:      strings.ToUpper(protocol),
		BytesSent:  bytesSent,
		BytesRecv:  bytesRecv,
		Retrans:    retrans,
		Resets:     resets,
		DurationMs: uint64(rand.Intn(450) + 10),
		PID:        pid,
		Process:    processName(protocol),
		Container:  "demo-container",
		Namespace:  "demo-ns",
		State:      "ESTABLISHED",
		FirstSeen:  now.Add(-time.Second),
		LastSeen:   now,
		Protocol:   protocol,
		Score:      scoreFlow(bytesSent, bytesRecv, retrans, resets),
	}
	c.flows[flowKey] = flow
	if len(c.flows) > 120 {
		c.trimOldestFlows()
	}
}

// processName maps a protocol label to a common system process name used in the demo.
func processName(protocol string) string {
	switch strings.ToUpper(protocol) {
	case "DNS":
		return "systemd-resolved"
	case "HTTP":
		return "nginx"
	case "MYSQL":
		return "mysqld"
	case "GRPC":
		return "grpc-server"
	default:
		return "demo-process"
	}
}

// classifyProto figures out the app-level protocol from a small amount of metadata.
//
// This is intentionally lightweight: eBPF does efficient transport-level introspection,
// while userspace adds protocol hints based on ports and behavior. This is much cheaper
// than full payload inspection and is sufficient for a local dashboard prototype.
func classifyProto(proto uint8, srcPort, dstPort uint16) string {
	switch proto {
	case 6:
		// TCP: use port hints as a quick classifier.
		switch {
		case dstPort == 53 || srcPort == 53:
			return "dns"
		case dstPort == 80 || srcPort == 80 || dstPort == 8080 || srcPort == 8080:
			return "http"
		case dstPort == 3306 || srcPort == 3306:
			return "mysql"
		case dstPort == 50051 || srcPort == 50051 || dstPort == 50052 || srcPort == 50052:
			return "grpc"
		default:
			return "tcp"
		}
	case 17:
		return "udp"
	default:
		return "unknown"
	}
}

// mapProtoName normalizes the protocol number into a user-visible string.
func mapProtoName(proto uint8) string {
	switch proto {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return "UNKNOWN"
	}
}

// scoreFlow computes a relative anomaly score for a flow.
//
// A higher score means the flow is suspicious or unusually active. This is deliberately simple
// and is intended for a dashboard demo rather than a production statistical model.
func scoreFlow(bytesSent, bytesRecv uint64, retransmits, resets uint32) float64 {
	score := 0.0
	score += float64(bytesSent) / 1024.0 / 8.0
	score += float64(bytesRecv) / 1024.0 / 10.0
	score += float64(retransmits) * 4.0
	score += float64(resets) * 9.0
	if score < 0 {
		return 0
	}
	return score
}

// ipv4ToString converts a raw uint32 IPv4 address to the standard dotted decimal representation.
func ipv4ToString(v uint32) string {
	bytesV := make([]byte, 4)
	binary.BigEndian.PutUint32(bytesV, v)
	return net.IP(bytesV).String()
}

// unsafeSizeOfBPFEvent returns the byte size of the BPF event struct.
//
// We need this value to avoid reading a short record and to validate the ring buffer payload.
func unsafeSizeOfBPFEvent() uintptr {
	return unsafe.Sizeof(bpfFlowEvent{})
}

// NOTE ON APIS:
// The design intentionally uses a small set of APIs that are common in kernel-enabled BPF
// projects:
//   - ebpf.LoadCollectionSpec() loads the compiled ELF object from disk.
//   - ebpf.NewCollection() instantiates the BPF programs and maps.
//   - ringbuf.NewReader() reads buffered events in a low-overhead, non-blocking style.
//
// These APIs are the core building blocks of a real Linux eBPF telemetry pipeline.
//
// Also important: the code avoids storing telemetry permanently. All events remain in memory
// for the lifetime of the process, and the web dashboard renders the most recent snapshots.

// The project intentionally keeps the event model small and easy to reason about so that
// individual students can inspect the full flow from kernel event to UI update in one pass.

// JSON export helper for UI consumption.
func (c *Collector) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.Snapshot())
}
