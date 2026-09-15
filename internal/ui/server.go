package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"ebpf_dpi/internal/collector"
)

// Server is a lightweight HTTP interface for the live dashboard.
//
// It serves:
//   - / : the HTML page that renders the dashboard
//   - /events : a server-sent events endpoint that streams live flow summaries
//
// This API intentionally avoids storing anything; it simply exposes the in-memory state from
// the collector on demand.
type Server struct {
	httpServer *http.Server
	collector  *collector.Collector
	refreshSec int
}

// NewServer creates a frontend server around the traffic collector.
func NewServer(c *collector.Collector, refreshSec int) *Server {
	if refreshSec <= 0 {
		refreshSec = 1
	}
	return &Server{collector: c, refreshSec: refreshSec}
}

// Run starts the HTTP server on the requested host and port.
func (s *Server) Run(host string, port int) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/events", s.handleEvents)
	mux.HandleFunc("/api/flows", s.handleFlows)
	mux.HandleFunc("/api/stats", s.handleStats)

	srv := &http.Server{
		Addr:           fmt.Sprintf("%s:%d", host, port),
		Handler:        mux,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   10 * time.Second,
		IdleTimeout:    15 * time.Second,
		ErrorLog:       log.Default(),
	}
	s.httpServer = srv
	log.Printf("dashboard available at http://%s:%d", host, port)
	return srv.ListenAndServe()
}

// Shutdown gracefully stops the HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer == nil {
		return nil
	}
	return s.httpServer.Shutdown(ctx)
}

// handleIndex serves a simple dashboard page.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	html := `
		<!doctype html>
		<html>
		<head>
			<meta charset="utf-8">
			<title>eBPF Flow Monitor</title>
			<style>
				body { font-family: sans-serif; background: #111827; color: #e5e7eb; margin: 0; padding: 20px; }
				.container { max-width: 1200px; margin: 0 auto; }
				h1 { margin-bottom: 8px; }
				.summary { display: grid; grid-template-columns: repeat(4, minmax(180px, 1fr)); gap: 16px; margin: 20px 0; }
				.card { background: #1f2937; border: 1px solid #374151; border-radius: 10px; padding: 16px; }
				table { width: 100%; border-collapse: collapse; margin-top: 20px; }
				th, td { border-bottom: 1px solid #374151; padding: 8px 10px; text-align: left; }
				th { color: #93c5fd; }
				.badge { display: inline-block; padding: 4px 8px; border-radius: 999px; background: #0f766e; color: #d1fae5; }
				#status { margin-top: 10px; color: #86efac; }
			</style>
		</head>
		<body>
			<div class="container">
				<h1>eBPF Flow Monitor</h1>
				<div id="status">Connecting to live events…</div>
				<div class="summary">
					<div class="card"><strong>Total flows</strong><div id="total-flows">0</div></div>
					<div class="card"><strong>Bytes sent</strong><div id="bytes-sent">0</div></div>
					<div class="card"><strong>Bytes recv</strong><div id="bytes-recv">0</div></div>
					<div class="card"><strong>Top protocol</strong><div id="top-proto">unknown</div></div>
				</div>
				<div class="summary">
					<div class="card"><strong>Alerts</strong><div id="alerts">none</div></div>
					<div class="card"><strong>Peak score</strong><div id="peak-score">0</div></div>
					<div class="card"><strong>Host</strong><div id="host-name">ubuntu</div></div>
					<div class="card"><strong>Namespace</strong><div id="namespace">default</div></div>
				</div>
				<div style="display:grid; grid-template-columns: 1.4fr 1fr; gap: 16px;">
					<div class="card">
						<h3>Top process activity</h3>
						<ul id="process-list"></ul>
					</div>
					<div class="card">
						<h3>Recent alerts</h3>
						<ul id="alert-list"></ul>
					</div>
				</div>
				<table>
					<thead>
						<tr>
							<th>Flow</th>
							<th>Proto</th>
							<th>Process</th>
							<th>Container</th>
							<th>Bytes sent</th>
							<th>Bytes recv</th>
							<th>Retrans</th>
							<th>Score</th>
						</tr>
					</thead>
					<tbody id="flow-table"></tbody>
				</table>
			</div>
			<script>
				const flowTable = document.getElementById('flow-table');
				const totalFlows = document.getElementById('total-flows');
				const bytesSent = document.getElementById('bytes-sent');
				const bytesRecv = document.getElementById('bytes-recv');
				const topProto = document.getElementById('top-proto');
				const peakScore = document.getElementById('peak-score');
				const alertsBox = document.getElementById('alerts');
				const status = document.getElementById('status');
				const processList = document.getElementById('process-list');
				const alertList = document.getElementById('alert-list');

				async function loadStats() {
					const res = await fetch('/api/stats');
					const data = await res.json();
					totalFlows.textContent = data.total_flows;
					bytesSent.textContent = data.bytes_sent;
					bytesRecv.textContent = data.bytes_recv;
					topProto.textContent = data.top_proto || 'unknown';
					peakScore.textContent = data.peak_score ? data.peak_score.toFixed(1) : '0';
					alertsBox.textContent = Array.isArray(data.alerts) && data.alerts.length ? data.alerts.length : 'none';

					processList.innerHTML = (data.top_processes || []).map(function(proc) {
						return '<li>' + proc.process + ' — ' + proc.bytes + ' bytes / ' + proc.flows + ' flows</li>';
					}).join('');

					alertList.innerHTML = (data.alerts || []).slice(0, 4).map(function(alert) {
						return '<li>' + alert + '</li>';
					}).join('');
				}

				async function loadFlows() {
					const res = await fetch('/api/flows');
					const rows = await res.json();
					flowTable.innerHTML = rows.map(function(flow) {
						return '<tr>' +
							'<td>' + flow.src_ip + ':' + flow.src_port + ' → ' + flow.dst_ip + ':' + flow.dst_port + '</td>' +
							'<td><span class="badge">' + flow.protocol + '</span></td>' +
							'<td>' + flow.process + '</td>' +
							'<td>' + (flow.container || 'host') + '</td>' +
							'<td>' + flow.bytes_sent + '</td>' +
							'<td>' + flow.bytes_recv + '</td>' +
							'<td>' + flow.retransmits + '</td>' +
							'<td>' + flow.score.toFixed(1) + '</td>' +
							'</tr>';
					}).join('');
				}

				async function refresh() {
					await loadStats();
					await loadFlows();
				}

				status.textContent = 'Live stream active';
				refresh();
				setInterval(refresh, 1000);
			</script>
		</body>
		</html>
	`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(html))
}

// handleEvents streams live JSON events using SSE.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	for {
		select {
		case <-r.Context().Done():
			return
		default:
			stats := s.collector.Stats()
			payload, err := json.Marshal(stats)
			if err != nil {
				continue
			}
			_, _ = fmt.Fprintf(w, "event: stats\ndata: %s\n\n", payload)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			time.Sleep(time.Duration(s.refreshSec) * time.Second)
		}
	}
}

// handleFlows returns the latest flow list as JSON.
func (s *Server) handleFlows(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	flows := s.collector.Snapshot()
	if err := json.NewEncoder(w).Encode(flows); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// handleStats returns aggregate stats as JSON.
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	stats := s.collector.Stats()
	if err := json.NewEncoder(w).Encode(stats); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// NOTE:
// This UI is deliberately simple. The purpose is educational clarity, not a production-grade
// frontend. The main idea is to show that the collector already has a real-time, in-memory
// dataset available for rendering. The dashboard is therefore a presentation layer only.
