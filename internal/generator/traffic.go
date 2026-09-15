package generator

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// TrafficGenerator runs a small set of real Linux traffic commands to produce live traffic
// for demonstration. This is not a full packet generation framework; it is a lightweight,
// reproducible traffic source that helps show the monitor working in a real Ubuntu runtime.
//
// The generator intentionally does not persist data. It just causes traffic to appear on the
// host so the eBPF monitor can observe it, classify it, and display it in the dashboard.
type TrafficGenerator struct {
	Stop chan struct{}
}

// NewTrafficGenerator creates a generator for realistic test traffic.
func NewTrafficGenerator() *TrafficGenerator {
	return &TrafficGenerator{Stop: make(chan struct{})}
}

// Start begins a small suite of traffic tasks. It is designed for local demo use.
func (g *TrafficGenerator) Start() {
	go func() {
		for {
			select {
			case <-g.Stop:
				return
			default:
				simulateTraffic()
				time.Sleep(2 * time.Second)
			}
		}
	}()
}

// Stop stops the generator.
func (g *TrafficGenerator) StopGenerator() {
	close(g.Stop)
}

// simulateTraffic runs a very small batch of traffic commands. This is intentionally simple and
// educational. It uses standard tools available on Ubuntu, or quietly exits if a tool is missing.
func simulateTraffic() {
	// DNS resolution produces an observable UDP/TCP session with low payload volume.
	// This is useful because DNS is one of the most common traffic types to classify in eBPF.
	if _, err := exec.LookPath("getent"); err == nil {
		_ = exec.Command("bash", "-lc", "getent hosts example.com >/dev/null 2>&1 || true").Run()
	}

	// HTTP traffic is easy to generate with curl. It is a very common flow type and helps show
	// classification in the dashboard.
	if _, err := exec.LookPath("curl"); err == nil {
		_ = exec.Command("bash", "-lc", "curl -sSfL http://example.com >/dev/null 2>&1 || true").Run()
	}

	// There is no requirement to store output. We are only creating a realistic network signal.
	// The monitor reads the kernel-side flow information and aggregates it in memory.
	if _, err := exec.LookPath("python3"); err == nil {
		cmd := `python3 -c "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(2); 
try:
    s.connect(('example.com', 80)); s.sendall(b'GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n'); s.recv(1024)
except Exception:
    pass
finally:
    s.close()"`
		_ = exec.Command("bash", "-lc", cmd).Run()
	}
}

// EchoHTTPStatus generates a simple HTTP response in the same process if needed for local demoing.
// It is a convenience helper when you want a minimal local service without external dependencies.
func EchoHTTPStatus() string {
	return strings.TrimSpace(fmt.Sprintf("OK at %s", time.Now().Format(time.RFC3339)))
}
