package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ebpf_dpi/internal/collector"
	"ebpf_dpi/internal/generator"
	"ebpf_dpi/internal/ui"
)

// main is the entry point for the traffic-analysis daemon.
//
// The application follows a simple design:
//   1. Start a collector that either loads real eBPF telemetry or generates demo data.
//   2. Start a local web UI that exposes a dashboard and an event stream.
//   3. Wait for a termination signal and shut everything down cleanly.
func main() {
	var (
		host       = flag.String("host", "0.0.0.0", "bind host for the dashboard")
		port       = flag.Int("port", 8080, "bind port for the dashboard")
		bpfObject  = flag.String("bpf-object", "bpf/flow_monitor.bpf.o", "path to the compiled BPF object file")
		demo       = flag.Bool("demo", false, "force demo mode even if a BPF object exists")
		refreshSec = flag.Int("refresh", 1, "dashboard update interval in seconds")
	)
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// A collector is the central in-memory store for flows and traffic events.
	// It exposes a Snapshot() method that the UI reads to render the dashboard.
	c := collector.NewCollector()

	// A real eBPF deployment would require root privileges and a compiled object file.
	// If the object file is missing, or the user explicitly requested demo mode,
	// we fall back to synthetic traffic so the dashboard still works for learning and demos.
	if *demo || !fileExists(*bpfObject) {
		log.Printf("BPF object %q not found or demo mode enabled; starting synthetic traffic generation", *bpfObject)
		go c.RunDemo()
	} else {
		log.Printf("Attempting to load eBPF object %q", *bpfObject)
		if err := c.StartBPF(*bpfObject); err != nil {
			log.Printf("BPF startup failed: %v; falling back to demo mode", err)
			go c.RunDemo()
		}
	}

	// Start the traffic generator in demo mode so the UI can show realistic traffic patterns
	// even without a real kernel capture. This is separate from the BPF collector and acts as a
	// safety net for local demonstration.
	if *demo || !fileExists(*bpfObject) {
		gen := generator.NewTrafficGenerator()
		gen.Start()
		defer gen.StopGenerator()
	}

	// The UI server is intentionally lightweight: it serves a local dashboard and
	// a server-sent events stream for the live data view. Nothing is persisted.
	srv := ui.NewServer(c, *refreshSec)
	go func() {
		if err := srv.Run(*host, *port); err != nil {
			log.Printf("UI server error: %v", err)
			stop()
		}
	}()

	// Keep the program alive until an interrupt or termination signal arrives.
	select {
	case <-ctx.Done():
		log.Println("shutdown requested; stopping traffic monitor")
	case <-time.After(24 * time.Hour):
		log.Println("application timeout reached; exiting")
	}

	// Close the server cleanly before exit.
	if err := srv.Shutdown(context.Background()); err != nil {
		log.Printf("UI shutdown error: %v", err)
	}
	log.Println("traffic monitor stopped")
}

// fileExists is a tiny utility used to decide whether the compiled BPF object is available.
func fileExists(path string) bool {
	stat, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !stat.IsDir()
}

// NOTE:
// The full BPF path is intentionally separated from the rest of the code so that the
// project still builds in learning/demo environments where root privileges or kernel
// headers are not available. The actual kernel capture is handled by the collector.
//
// For a real Ubuntu deployment, you would run:
//   make bpf
//   sudo go run . --host 0.0.0.0 --port 8080
//
// This is the simplest route to a live demo without storing any telemetry permanently.

// Additional design note:
// The current implementation is intentionally a “practical skeleton” rather than a full
// production kernel monitoring pipeline. It demonstrates the architecture clearly:
//   - BPF ring buffer event ingestion
//   - in-memory flow aggregation
//   - live web dashboard
//   - demo fallback when eBPF is unavailable
//
// The code is structured so you can keep extending it with real connection probing,
// container metadata, protocol detection, and anomaly scoring without changing the UI flow.

// Example demo commands:
//   go run . --demo
//   curl http://localhost:8080/
//   curl http://localhost:8080/events
//
// The /events endpoint emits a plain-text SSE stream that can be consumed by a browser.
// A browser can fetch the main page and render the live values without persistence.

// The dashboard contains no database or storage layer by design.
// It is a real-time, in-memory view of traffic behavior. This matches the requirement:
// "No need to store anything anywhere; after the analysis it may be shown in the dashboard."

func init() {
	// This init block exists to make the project ergonomic when used in a learning
	// environment. The monitoring logic is fully contained in the collector and UI packages.
	// There is intentionally almost no global state here.
	fmt.Println("Starting eBPF Flow Monitor")
}
