# eBPF Flow Monitor

A lightweight Linux traffic-analysis project for Ubuntu that collects live flow metadata, classifies traffic patterns, and displays the results in a local web dashboard without persisting anything to disk.

This project is designed as a learning-focused and demo-friendly implementation of an eBPF-based network monitor. It shows the core architecture for:

- kernel-side traffic observation
- in-memory aggregation in userspace
- protocol classification hints
- process and container labeling metadata
- real-time dashboard rendering

No database or permanent storage is used. All telemetry remains in memory while the service is running.

## Project goal

Build a tool that watches TCP/UDP traffic at the kernel level and summarizes:

- source and destination IP and port
- connection duration
- bytes sent and received
- retransmits and resets
- per-process ownership
- protocol classification: DNS, HTTP, gRPC, MySQL, etc.

The project is intentionally structured so it can run in two modes:

1. Demo mode: synthetic traffic is generated locally to visualize behavior in a browser.
2. eBPF mode: a compiled BPF object can be loaded on Ubuntu to capture real kernel events.

## Architecture

The project follows a simple real-time pipeline:

1. Traffic is generated or observed on the Ubuntu host.
2. eBPF code emits compact flow events from the kernel.
3. A Go collector reads those events from a ring buffer.
4. The collector aggregates flows in memory.
5. A small web dashboard renders the live results.

High-level flow:

```text
Traffic on Ubuntu host / containers
        |
        v
   eBPF kernel hooks
        |
        v
    Ring buffer events
        |
        v
  Go collector (in-memory only)
        |
        v
  Local web dashboard / live JSON API
```

## Folder layout

```text
ebpf_dpi/
├── Makefile
├── README.md
├── go.mod
├── main.go
├── bpf/
│   └── flow_monitor.bpf.c
├── internal/
│   ├── collector/
│   │   └── collector.go
│   ├── generator/
│   │   └── traffic.go
│   ├── labels/
│   │   └── labels.go
│   └── ui/
│       └── server.go
└── ...
```

## How it works

### 1. Kernel observations

The BPF code in [bpf/flow_monitor.bpf.c](bpf/flow_monitor.bpf.c) creates a ring buffer map and emits compact flow summaries from the kernel. This is the part that would normally hook into socket lifecycle and network-state events.

### 2. Userspace capture

The collector in [internal/collector/collector.go](internal/collector/collector.go) does the following:

- loads the BPF object from disk
- reads ring buffer events
- decodes the binary payload into a Go flow structure
- stores the flow in memory only
- calculates summary stats and anomaly-like scoring

### 3. Protocol classification

The collector applies lightweight protocol detection using:

- port hints (DNS, HTTP, MySQL, gRPC)
- TCP/UDP metadata
- simple heuristic scoring

This keeps the implementation lightweight and understandable while still showing the pattern.

### 4. Process and container metadata

The labeling logic in [internal/labels/labels.go](internal/labels/labels.go) tries to infer:

- process name
- PID
- container-like cgroup information
- namespace hints

This is helpful for showing which process owns a flow, but it remains intentionally best-effort and non-persistent.

### 5. UI dashboard

The web server in [internal/ui/server.go](internal/ui/server.go) exposes:

- a local HTML dashboard
- JSON endpoints for current flows
- summary stats for process activity and alerts

The dashboard refreshes automatically so the user can view live traffic behavior without any storage layer.

## Demo mode

The easiest way to run this project is in demo mode:

```bash
cd /home/felicity/learn/ebpf_dpi
go run . --demo
```

This starts:

- the lightweight collector
- a traffic generator for local demo traffic
- the local dashboard on port 8080

Then visit:

```text
http://localhost:8080
```

## Real BPF mode

To use the compiled BPF object on Ubuntu, first build it:

```bash
cd /home/felicity/learn/ebpf_dpi
make bpf
```

Then run:

```bash
sudo go run .
```

This attempts to load the compiled BPF object and start the ring-buffer reader. If the object is missing or privileges are unavailable, the application falls back to demo mode automatically.

## Required tooling

For the local build and demo route, you need:

- Go 1.22+
- clang
- llvm-strip
- a recent Ubuntu or Linux kernel

For the real BPF path, you also need:

- root access or CAP_BPF privileges
- suitable kernel support for the BPF hooks you enable
- a kernel with BPF and related tracing support

## Notes

This project is intentionally designed as a practical prototype rather than a production-ready production monitor. It focuses on clarity and teachability:

- the kernel and userspace boundary is obvious
- telemetry stays in memory only
- the runtime dashboard is simple and readable
- the structure is easy to extend toward real traffic inspection and anomaly detection

## Next enhancements

Possible future improvements include:

- deeper TCP/UDP socket event tracing
- per-container cgroup tagging from Docker/Kubernetes
- more accurate flow state tracking
- packet budget and sampling controls
- anomaly detection for resets, spikes, and retransmission storms
- charting and richer frontend visualization

## Quick start summary

```bash
cd /home/felicity/learn/ebpf_dpi
go run . --demo
```

Then open:

```text
http://localhost:8080
```

This gives you a live in-memory view of traffic behavior without storing anything anywhere.
