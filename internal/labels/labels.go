package labels

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ProcessMeta adds lightweight metadata to a flow record without storing anything permanently.
// The data is computed at runtime from the Linux process tree and is meant to enrich the UI.
type ProcessMeta struct {
	Process   string
	PID       uint32
	Container string
	Namespace string
	Cgroup    string
}

// GetProcessMetadata fetches a process's metadata from the current Linux environment.
//
// This is intentionally lightweight and best-effort. The code tries to identify:
//   - process name
//   - container ID via cgroup paths
//   - namespace from proc metadata
//
// If the process is not available or the system is not containerized, it falls back to a
// default label so the UI still renders cleanly.
func GetProcessMetadata(pid uint32, process string) ProcessMeta {
	meta := ProcessMeta{
		PID:       pid,
		Process:   strings.TrimSpace(process),
		Container: "host",
		Namespace: "default",
		Cgroup:    "host",
	}

	if meta.Process == "" {
		meta.Process = "unknown"
	}

	procDir := filepath.Join("/proc", strconv.Itoa(int(pid)))
	if _, err := os.Stat(procDir); err != nil {
		return meta
	}

	// /proc/<pid>/cgroup usually contains lines such as:
	//   0::/system.slice/docker-<containerid>.scope
	// This lets us detect container boundaries without a full orchestrator integration.
	cgroupPath := filepath.Join(procDir, "cgroup")
	if data, err := os.ReadFile(cgroupPath); err == nil {
		text := string(data)
		for _, line := range strings.Split(text, "\n") {
			if strings.Contains(line, "docker") || strings.Contains(line, "containerd") || strings.Contains(line, "kubepods") {
				parts := strings.Split(line, ":")
				if len(parts) >= 3 {
					meta.Cgroup = parts[len(parts)-1]
					if idx := strings.Index(meta.Cgroup, "docker-"); idx >= 0 {
						meta.Container = meta.Cgroup[idx+len("docker-"):]
						if len(meta.Container) > 12 {
							meta.Container = meta.Container[:12]
						}
					}
				}
			}
		}
	}

	// Some distributions put the container ID in the path and it is easy to infer.
	if meta.Container == "host" && strings.Contains(meta.Cgroup, "containerd") {
		meta.Container = "containerd"
	}

	nsPath := filepath.Join(procDir, "ns")
	if entries, err := os.ReadDir(nsPath); err == nil {
		for _, e := range entries {
			if e.Name() == "ipc" || e.Name() == "mnt" || e.Name() == "net" || e.Name() == "pid" {
				meta.Namespace = "linux-ns"
				break
			}
		}
	}

	return meta
}

// ProcessLabelFor is the user-facing short label used in the dashboard.
func ProcessLabelFor(process string, pid uint32) string {
	meta := GetProcessMetadata(pid, process)
	if meta.Container != "host" {
		return fmt.Sprintf("%s (%s)", meta.Process, meta.Container)
	}
	return meta.Process
}
