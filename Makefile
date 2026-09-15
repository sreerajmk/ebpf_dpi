# This Makefile compiles the BPF object used by the userspace collector.
# The build is intentionally simple and expects a recent Ubuntu/Linux environment
# with clang, llvm-strip, and libbpf headers available.
#
# Usage:
#   make bpf
#   go run .
#
# If you run the application without the object present, the server automatically
# starts in demo mode so the dashboard still works without root privileges.

BPF_DIR = bpf
BPF_SRC = $(BPF_DIR)/flow_monitor.bpf.c
BPF_OBJ = $(BPF_DIR)/flow_monitor.bpf.o

.PHONY: bpf clean

bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC)
	@mkdir -p $(BPF_DIR)
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
		-I/usr/src/linux-headers-$(shell uname -r)/include \
		-I/usr/include \
		-c $(BPF_SRC) -o $(BPF_OBJ)
	llvm-strip -g $(BPF_OBJ)

clean:
	rm -f $(BPF_OBJ)
