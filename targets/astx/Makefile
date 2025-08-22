# Makefile for ASTx / CheerpX workflow

ROOT_DIR := /workspace/..
DEV_IMAGE := astx-dev
RUNTIME_IMAGE := astx-runtime
WEBVM_IMAGE := astx-webvm
DEB_FILE := /workspace/packages/astx_u32.deb
PAYLOAD_DIR := /workspace/unpacked/rootfs

# Common build and run flags
PLATFORM_DEV := linux/amd64
PLATFORM_WEBVM := linux/i386
DOCKERFILE := platform/Dockerfile

NATIVE ?=

# Common podman command patterns
PODMAN_CMD := podman $(if $(NATIVE),--connection lazarus)

# Default target
.PHONY: all
all: build-dev

# --- Payload unpack ---
.PHONY: unpack
unpack:
	@echo "[*] Unpacking $(DEB_FILE) into $(PAYLOAD_DIR)..."
	mkdir -p unpacked/rootfs unpacked/meta
	$(PODMAN_CMD) run --rm -it --platform $(PLATFORM_DEV) -v $(PWD):/workspace debian:bookworm-slim \
		sh -c "dpkg-deb -x /workspace/packages/astx_u32.deb /workspace/unpacked/rootfs && \
		       dpkg-deb -e /workspace/packages/astx_u32.deb /workspace/unpacked/meta"

# --- Build containers ---
.PHONY: build-dev
# --- Build containers ---
.PHONY: build-dev
build-dev:
	@echo "[*] Building dev image ($(DEV_IMAGE))..."
	$(PODMAN_CMD) build -f $(DOCKERFILE) --build-arg TARGETPLATFORM=$(PLATFORM_DEV) --target dev -t $(DEV_IMAGE) .

.PHONY: build-runtime
build-runtime:
	@echo "[*] Building runtime image ($(RUNTIME_IMAGE))..."
	$(PODMAN_CMD) build -f $(DOCKERFILE) --build-arg TARGETPLATFORM=$(PLATFORM_DEV) --target runtime -t $(RUNTIME_IMAGE) .

.PHONY: build-webvm
build-webvm:
	@echo "[*] Building WebVM image ($(WEBVM_IMAGE))..."
	$(PODMAN_CMD) build -f $(DOCKERFILE) --build-arg TARGETPLATFORM=$(PLATFORM_WEBVM) --target webvm -t $(WEBVM_IMAGE) .

.PHONY: build
build: build-dev build-runtime build-webvm

# --- Run containers ---
.PHONY: shell shell-dev shell-runtime shell-webvm
shell: shell-dev

shell-dev:
	@echo "[*] Starting interactive shell in dev container..."
	mkdir -p specimen/logs specimen/cfg
	$(PODMAN_CMD) run --rm -it --platform $(PLATFORM_DEV) -p 8080:8080 -p 27042:27042 \
		-v $(PWD):/workspace \
		-v $(PWD)/specimen/Logs:/opt/AhnLab/ASTx/Logs \
		-v $(PWD)/specimen/cfg:/opt/AhnLab/ASTx/cfg \
		-v $(PWD)/specimen/ConfigFile:/opt/AhnLab/ASTx/ConfigFile \
		-v $(PWD)/tools:/tmp/webroot/astx/policy:ro \
		$(DEV_IMAGE)

shell-runtime:
	@echo "[*] Starting interactive shell in runtime container..."
	$(PODMAN_CMD) run --rm -it --platform $(PLATFORM_DEV) --entrypoint='["/bin/bash"]' $(RUNTIME_IMAGE)

shell-webvm:
	@echo "[*] Starting interactive shell in webvm container as user..."
	$(PODMAN_CMD) run --rm -it --platform $(PLATFORM_WEBVM) --user user $(WEBVM_IMAGE)

# --- Static analysis ---
.PHONY: analyze
analyze: unpack
	@echo "[*] Running static analysis inside dev container..."
	$(PODMAN_CMD) run --rm -it --platform $(PLATFORM_DEV) -v $(PWD):/workspace $(DEV_IMAGE) /workspace/tools/package_analyze.sh /workspace/unpacked/rootfs /workspace/unpacked/meta /workspace/analysis

# --- Runtime tracing (QEMU_STRACE) ---
.PHONY: trace trace-network
trace:
	@echo "[*] Running with QEMU syscall tracing..."
	mkdir -p analysis
	$(PODMAN_CMD) run --rm -it --platform $(PLATFORM_DEV) -p 8080:8080 -e QEMU_STRACE=1 $(RUNTIME_IMAGE)

trace-network:
	@echo "[*] Tracing network syscalls only..."
	mkdir -p analysis
	QEMU_STRACE=1 $(PODMAN_CMD) run --rm -it --platform $(PLATFORM_DEV) -p 8080:8080 $(RUNTIME_IMAGE) 2>&1 | grep -E "(socket|bind|connect|accept|send|recv)"

# --- Build ext2 filesystem images (uses podman machine ssh) ---
.PHONY: extract
extract:
	@echo "[*] Creating WebVM ext2 filesystem image for CheerpX..."
	@echo "[*] Using podman machine SSH to preserve permissions..."
	@# Clean up any existing containers/files
	$(PODMAN_CMD) rm -f "astx-webvm-container" >/dev/null 2>&1 || true
	rm -f dist/astx-webvm.ext2
	mkdir -p dist
	@# Create container from WebVM image
	$(PODMAN_CMD) create --name "astx-webvm-container" "$(WEBVM_IMAGE)" >/dev/null
	@# Run extraction inside podman machine VM (preserves permissions)
	podman machine ssh -- '\
		podman rm -f astx-webvm-container >/dev/null 2>&1 || true && \
		rm -rf /tmp/fs-webvm && \
		podman create --name astx-webvm-container $(WEBVM_IMAGE) >/dev/null && \
		mkdir -p /tmp/fs-webvm && \
		podman unshare podman cp astx-webvm-container:/ /tmp/fs-webvm/ && \
		podman unshare mkfs.ext2 -b 4096 -d /tmp/fs-webvm/ /tmp/astx-webvm.ext2 400M && \
		podman rm -f astx-webvm-container >/dev/null'
	@# Copy ext2 file from VM to host
	podman machine ssh -- 'cat /tmp/astx-webvm.ext2' > dist/astx-webvm.ext2
	@# Clean up VM
	podman machine ssh -- 'rm -f /tmp/astx-webvm.ext2 && rm -rf /tmp/fs-webvm'
	@echo "Created CheerpX-compatible WebVM image:"
	@ls -lh dist/astx-webvm.ext2
	@# Clean up host container
	$(PODMAN_CMD) rm -f "astx-webvm-container" >/dev/null

# --- Clean ---
.PHONY: clean
clean:
	@echo "[*] Cleaning up build artifacts..."
	rm -rf unpacked/ dist/ analysis/
