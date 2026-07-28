# AIVPN — unified build system
# All targets run from the repository root.
#
#   make          → show this help
#   make server   → build Linux x86_64 server release
#   make ios      → build iOS IPA  (macOS + Xcode required)
#   make macos    → build macOS .app + .pkg + .dmg

.DEFAULT_GOAL := help
MAKEFLAGS     += --no-print-directory

# Ensure rustup-managed cargo/rustc take priority over any system package.
export PATH := $(HOME)/.cargo/bin:$(PATH)

APP_VERSION := $(shell awk -F'"' '/^\[workspace\.package\]/{p=1} p && /^version/{print $$2; exit}' Cargo.toml)

# iOS Apple Team ID — pass as: make ios TEAM_ID=AB12CD34EF
TEAM_ID ?=

# ─────────────────────────────────────────────────────────────────────────────
# Phony targets
# ─────────────────────────────────────────────────────────────────────────────
# MikroTik image tag — make mikrotik IMAGE=myrepo/aivpn-mikrotik:latest
IMAGE    ?= infosave2007/aivpn-mikrotik:latest

# server-deploy: remote SSH user and install dir.
# USER is only honored when given on the command line (make server-deploy
# USER=ubuntu ...) — the inherited environment USER (local login) is ignored.
ifeq ($(origin USER),command line)
RUSER  ?= $(USER)
else
RUSER  ?= root
endif
REMOTE ?= /opt/aivpn

.PHONY: help setup check test clippy fmt mask-gate swift-parse \
        server server-tiny client server-docker \
        server-arm64 client-arm64 \
        server-musl-armv7 server-musl-mipsel server-musl-aarch64 server-musl-aarch64-full \
        client-musl-armv7 client-musl-mipsel client-musl-aarch64 \
        windows windows-docker ios macos linux-appimage \
        kernel kernel-install \
        mikrotik mikrotik-local \
        openwrt \
        android \
        web web-docker web-dev \
        deploy server-deploy test-docker clean clean-releases

# ─────────────────────────────────────────────────────────────────────────────
# Help
# ─────────────────────────────────────────────────────────────────────────────
help:
	@printf "AIVPN Build System  v%s\n\n" "$(APP_VERSION)"
	@printf "  Dev\n"
	@printf "    %-40s %s\n" "make setup"               "Install dev tools, run clippy + tests"
	@printf "    %-40s %s\n" "make check"               "cargo check (fast)"
	@printf "    %-40s %s\n" "make test"                "cargo test --workspace"
	@printf "    %-40s %s\n" "make clippy"              "cargo clippy --all-targets"
	@printf "    %-40s %s\n" "make fmt"                 "cargo fmt --all"
	@printf "    %-40s %s\n" "make mask-gate"           "nDPI-gate every assets/masks/*.json (R2 Phase A)"
	@printf "    %-40s %s\n" "make swift-parse"         "Syntax-check platforms/ios + platforms/macos (no Xcode needed)"
	@printf "\n  Server / Client — Linux x86_64\n"
	@printf "    %-40s %s\n" "make server"              "Full server [management-api,metrics,neural]"
	@printf "    %-40s %s\n" "make server-tiny"         "Minimal server (bare VPN gateway)"
	@printf "    %-40s %s\n" "make client"              "→ releases/aivpn-client-linux-x86_64"
	@printf "    %-40s %s\n" "make server-docker"       "Build server via Docker (minimal deps)"
	@printf "\n  Cross-compile — Linux ARM / MUSL\n"
	@printf "    %-40s %s\n" "make server-arm64"        "glibc arm64 (Docker)"
	@printf "    %-40s %s\n" "make client-arm64"        "glibc arm64 (Docker)"
	@printf "    %-40s %s\n" "make server-musl-armv7"   "musl static armv7"
	@printf "    %-40s %s\n" "make server-musl-mipsel"  "musl static mipsel"
	@printf "    %-40s %s\n" "make server-musl-aarch64" "musl static aarch64"
	@printf "    %-40s %s\n" "make server-musl-aarch64-full" "musl static aarch64 [management-api,metrics,neural]"
	@printf "    %-40s %s\n" "make client-musl-armv7"   "musl static armv7"
	@printf "    %-40s %s\n" "make client-musl-mipsel"  "musl static mipsel"
	@printf "    %-40s %s\n" "make client-musl-aarch64" "musl static aarch64"
	@printf "\n  Platform\n"
	@printf "    %-40s %s\n" "make windows"             "Windows GUI + zip  (cross from Linux)"
	@printf "    %-40s %s\n" "make ios [TEAM_ID=XX]"    "iOS IPA            (macOS + Xcode only)"
	@printf "    %-40s %s\n" "make macos"               "macOS .app + .pkg + .dmg (macOS only)"
	@printf "    %-40s %s\n" "make linux-appimage"      "Linux AppImage"
	@printf "\n  Kernel module (Linux 6.1+, requires kernel headers)\n"
	@printf "    %-40s %s\n" "make kernel"              "Build aivpn-linux-kernel .ko (+ XDP BPF if clang)"
	@printf "    %-40s %s\n" "make kernel-install"      "Install kernel module + depmod (root)"
	@printf "\n  MikroTik RouterOS container\n"
	@printf "    %-40s %s\n" "make mikrotik [IMAGE=x]"  "Build + push multi-arch manifest to Docker Hub"
	@printf "    %-40s %s\n" "make mikrotik-local"      "Build single-arch image locally (no push)"
	@printf "\n  OpenWrt package\n"
	@printf "    %-40s %s\n" "make openwrt"             "Build musl client binaries for ARMv7/MIPSel/AArch64"
	@printf "\n  Android\n"
	@printf "    %-40s %s\n" "make android"             "Build Android APK (requires SDK+NDK)"
	@printf "\n  Web management panel\n"
	@printf "    %-40s %s\n" "make web"                 "Build aivpn-web panel → platforms/aivpn-web/dist/"
	@printf "    %-40s %s\n" "make web-docker"          "Build aivpn-web:latest Docker image"
	@printf "    %-40s %s\n" "make web-dev"             "Start aivpn-web dev servers (Hono + SvelteKit)"
	@printf "\n  Deploy\n"
	@printf "    %-40s %s\n" "make deploy"              "Deploy server to VPS via Docker"
	@printf "\n  Clean\n"
	@printf "    %-40s %s\n" "make clean"               "cargo clean + kernel module objects"
	@printf "    %-40s %s\n" "make clean-releases"      "Remove releases/"
	@printf "\n"

# ─────────────────────────────────────────────────────────────────────────────
# Dev
# ─────────────────────────────────────────────────────────────────────────────
setup:
	@if ! command -v cargo >/dev/null 2>&1; then \
	    echo "Installing Rust via rustup..."; \
	    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh; \
	    . $$HOME/.cargo/env; \
	fi
	@echo "Rust: $$(rustc --version)"
	@command -v cargo-watch >/dev/null 2>&1 || cargo install cargo-watch
	@command -v cargo-audit >/dev/null 2>&1 || cargo install cargo-audit
	cargo clippy --all-targets --all-features -- -D warnings
	cargo test --workspace

check:
	cargo check --workspace

test:
	cargo test --workspace

clippy:
	cargo clippy --all-targets --all-features -- -D warnings

fmt:
	cargo fmt --all

# Offline nDPI provenance gate (R2 Phase A). Synthesises every mask's real
# uplink packets and fails if nDPI does not classify a mask as its declared
# target protocol. Gracefully SKIPS (exit 0) when the research DPI toolchain
# (nDPI + maskpcap under the gitignored research/ tree) is not built, so devs
# without it are not blocked. See docs/R2_PHASE_A.md.
mask-gate:
	scripts/ci-mask-gate.sh

# Syntax gate for the Apple sources. They can only be BUILT on macOS, so edits
# to platforms/ios and platforms/macos otherwise go in unverified until the
# operator builds on a Mac. `swiftc -parse` needs no Apple SDK, so it runs on
# Linux and catches truncated/malformed edits (not type errors). Gracefully
# SKIPS when no Swift toolchain is installed. See docs in the script.
swift-parse:
	scripts/ci-swift-parse.sh

# ─────────────────────────────────────────────────────────────────────────────
# Server / Client — Linux x86_64
# ─────────────────────────────────────────────────────────────────────────────
releases/:
	@mkdir -p releases

# Full server: the features a real deployment needs — management-api (web panel
# + /run/aivpn/api.sock), metrics (dashboard time-series), neural (DPI-driven
# mask rotation). This is the canonical release artifact. Use `make server-tiny`
# for a bare VPN-gateway build with none of these.
server: releases/
	cargo build --release --bin aivpn-server --features "management-api,metrics,neural" -p aivpn-server
	cp target/release/aivpn-server releases/aivpn-server-linux-x86_64
	chmod +x releases/aivpn-server-linux-x86_64
	@echo "→ releases/aivpn-server-linux-x86_64  [management-api,metrics,neural]  ($$(du -h releases/aivpn-server-linux-x86_64 | cut -f1))"

# Minimal server: default features only (no management-api/metrics/neural) — a
# lean pure VPN gateway. The web panel and metrics dashboard will NOT work
# against this build; use `make server` for those.
server-tiny: releases/
	cargo build --release --bin aivpn-server -p aivpn-server
	cp target/release/aivpn-server releases/aivpn-server-linux-x86_64-tiny
	chmod +x releases/aivpn-server-linux-x86_64-tiny
	@echo "→ releases/aivpn-server-linux-x86_64-tiny  [minimal]  ($$(du -h releases/aivpn-server-linux-x86_64-tiny | cut -f1))"

client: releases/
	cargo build --release -p aivpn-client --features ssh-install
	cp target/release/aivpn-client releases/aivpn-client-linux-x86_64
	chmod +x releases/aivpn-client-linux-x86_64
	@echo "→ releases/aivpn-client-linux-x86_64  ($$(du -h releases/aivpn-client-linux-x86_64 | cut -f1))"

server-docker: releases/
	@set -e; \
	CTR="aivpn-server-rel-$$RANDOM"; \
	docker build --target builder -t aivpn-server-builder:release -f Dockerfile .; \
	docker create --name $$CTR aivpn-server-builder:release >/dev/null; \
	trap "docker rm -f $$CTR >/dev/null 2>&1 || true" EXIT; \
	docker cp $$CTR:/app/target/release/aivpn-server releases/aivpn-server-linux-x86_64; \
	chmod +x releases/aivpn-server-linux-x86_64; \
	echo "→ releases/aivpn-server-linux-x86_64"

# ─────────────────────────────────────────────────────────────────────────────
# ARM64 cross-compile (Docker, glibc)
# ─────────────────────────────────────────────────────────────────────────────
server-arm64: releases/
	docker run --rm -v "$$(pwd)":/aivpn -w /aivpn \
	  -e CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
	  -e CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
	  debian:bookworm bash -c " \
	    apt-get update -qq && \
	    apt-get install -y curl build-essential gcc-aarch64-linux-gnu libssl-dev pkg-config && \
	    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable && \
	    . \$$HOME/.cargo/env && \
	    rustup target add aarch64-unknown-linux-gnu && \
	    cargo build --release -p aivpn-server --target aarch64-unknown-linux-gnu"
	cp target/aarch64-unknown-linux-gnu/release/aivpn-server releases/aivpn-server-linux-arm64
	chmod +x releases/aivpn-server-linux-arm64
	@echo "→ releases/aivpn-server-linux-arm64"

client-arm64: releases/
	docker run --rm -v "$$(pwd)":/aivpn -w /aivpn \
	  -e CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
	  -e CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
	  -e OPENSSL_NO_VENDOR=1 \
	  -e PKG_CONFIG_ALLOW_CROSS=1 \
	  -e PKG_CONFIG_PATH=/usr/lib/aarch64-linux-gnu/pkgconfig \
	  debian:bookworm bash -c " \
	    dpkg --add-architecture arm64 && \
	    apt-get update -qq && \
	    apt-get install -y curl build-essential gcc-aarch64-linux-gnu \
	      pkg-config libssl-dev:arm64 crossbuild-essential-arm64 && \
	    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable && \
	    . \$$HOME/.cargo/env && \
	    rustup target add aarch64-unknown-linux-gnu && \
	    cargo build --release -p aivpn-client --features ssh-install --target aarch64-unknown-linux-gnu"
	cp target/aarch64-unknown-linux-gnu/release/aivpn-client releases/aivpn-client-linux-arm64
	chmod +x releases/aivpn-client-linux-arm64
	@echo "→ releases/aivpn-client-linux-arm64"

# ─────────────────────────────────────────────────────────────────────────────
# MUSL static builds
# Internal macro — $(call _musl,server|client,image-tag,target-triple,artifact-suffix[,cargo-features])
# The 5th arg is optional: a comma-separated cargo --features list. Pass it via
# a variable reference (e.g. $(FULL_SERVER_FEATURES)) rather than a literal
# comma-containing string, since $(call ...) itself splits arguments on commas.
# ─────────────────────────────────────────────────────────────────────────────
define _musl
	@mkdir -p releases
	@set -e; \
	CRATE="aivpn-$(1)"; \
	IMAGE="aivpn-$(1)-$(3):musl"; \
	ARTIFACT="releases/aivpn-$(1)-linux-$(4)"; \
	FEATURES="$(5)"; \
	CTR="aivpn-$(1)-$$(echo $$RANDOM)"; \
	TMPDF="$$(mktemp /tmp/Dockerfile.musl.XXXXXX)"; \
	{ printf 'ARG MUSL_IMAGE_TAG\n'; \
	  printf 'FROM messense/rust-musl-cross:$${MUSL_IMAGE_TAG} AS builder\n'; \
	  printf 'ARG TARGET_TRIPLE CRATE_NAME BINARY_NAME BUILD_FEATURES\n'; \
	  printf 'WORKDIR /app\n'; \
	  printf 'COPY Cargo.toml ./\n'; \
	  printf 'COPY crates/aivpn-common crates/aivpn-common/\n'; \
	  printf 'COPY crates/aivpn-server crates/aivpn-server/\n'; \
	  printf 'COPY crates/aivpn-client crates/aivpn-client/\n'; \
	  printf 'COPY crates/aivpn-windows crates/aivpn-windows/\n'; \
	  printf 'COPY crates/aivpn-linux crates/aivpn-linux/\n'; \
	  printf 'COPY crates/aivpn-android-core crates/aivpn-android-core/\n'; \
	  printf 'COPY crates/aivpn-ios-core crates/aivpn-ios-core/\n'; \
	  printf 'COPY assets/masks assets/masks/\n'; \
	  printf 'RUN if [ -n "$$BUILD_FEATURES" ]; then cargo build --release --target "$$TARGET_TRIPLE" -p "$$CRATE_NAME" --bin "$$BINARY_NAME" --features "$$BUILD_FEATURES"; else cargo build --release --target "$$TARGET_TRIPLE" -p "$$CRATE_NAME" --bin "$$BINARY_NAME"; fi\n'; \
	} > "$$TMPDF"; \
	trap "rm -f $$TMPDF; docker rm -f $$CTR >/dev/null 2>&1 || true" EXIT; \
	docker build \
	  --build-arg MUSL_IMAGE_TAG="$(2)" \
	  --build-arg TARGET_TRIPLE="$(3)" \
	  --build-arg CRATE_NAME="$$CRATE" \
	  --build-arg BINARY_NAME="$$CRATE" \
	  --build-arg BUILD_FEATURES="$$FEATURES" \
	  -t "$$IMAGE" -f "$$TMPDF" .; \
	docker create --name "$$CTR" "$$IMAGE" >/dev/null; \
	docker cp "$$CTR:/app/target/$(3)/release/$$CRATE" "$$ARTIFACT"; \
	chmod +x "$$ARTIFACT"; \
	echo "→ $$ARTIFACT ($$(du -h $$ARTIFACT | cut -f1))"
endef

server-musl-armv7:
	$(call _musl,server,armv7-musleabihf,armv7-unknown-linux-musleabihf,armv7-musleabihf)

server-musl-mipsel:
	$(call _musl,server,mipsel-musl,mipsel-unknown-linux-musl,mipsel-musl)

server-musl-aarch64:
	$(call _musl,server,aarch64-musl,aarch64-unknown-linux-musl,aarch64-musl)

# Full-feature aarch64 server (musl static, same feature set as `make server`:
# management-api + metrics + neural). Produces releases/aivpn-server-linux-aarch64
# — this is the release asset name a future deploy/install-server.sh downloads
# for aarch64 hosts (paired with x86_64's releases/aivpn-server-linux-x86_64).
#
# Cross-compile risk note (checked against Cargo.toml, 2026-07-23): management-api
# pulls axum/tower/hyper/hyper-util/tokio-stream/anyhow, metrics pulls prometheus
# (its protobuf encoding dep is the pure-Rust `protobuf` crate — no protoc/cmake
# needed), neural pulls aivpn-common's dpi-gate (dashmap only). None of these add
# a C library dependency beyond what the existing default-feature
# server-musl-aarch64 target already links, so this musl static build is
# expected to succeed the same way. If a future dependency bump pulls a C lib
# (openssl, onnxruntime, etc.) into any of these features, the musl static
# link will start failing here; the fallback is a glibc build via the
# server-arm64 Docker/Debian path (add --features to that target's cargo
# invocation) since glibc dynamic linking tolerates C deps musl static
# linking does not.
FULL_SERVER_FEATURES := management-api,metrics,neural

server-musl-aarch64-full:
	$(call _musl,server,aarch64-musl,aarch64-unknown-linux-musl,aarch64,$(FULL_SERVER_FEATURES))

client-musl-armv7:
	$(call _musl,client,armv7-musleabihf,armv7-unknown-linux-musleabihf,armv7-musleabihf)

client-musl-mipsel:
	$(call _musl,client,mipsel-musl,mipsel-unknown-linux-musl,mipsel-musl)

client-musl-aarch64:
	$(call _musl,client,aarch64-musl,aarch64-unknown-linux-musl,aarch64-musl)

# ─────────────────────────────────────────────────────────────────────────────
# Windows GUI (cross-compile from Linux)
# Requires: rust x86_64-pc-windows-gnu, mingw-w64, zip, [makensis]
# ─────────────────────────────────────────────────────────────────────────────
windows: releases/
	@set -e; \
	TARGET=x86_64-pc-windows-gnu; \
	RELEASE_DIR="target/$$TARGET/release"; \
	PACKAGE_DIR=releases/aivpn-windows-gui; \
	ZIP_NAME=releases/aivpn-windows-gui.zip; \
	if ! rustup target list --installed | grep -q "$$TARGET"; then \
	    echo "Installing target $$TARGET..."; \
	    rustup target add "$$TARGET"; \
	fi; \
	echo "Building aivpn-client.exe..."; \
	cargo build --release --target "$$TARGET" -p aivpn-client --features ssh-install; \
	echo "Building aivpn.exe (GUI)..."; \
	cargo build --release --target "$$TARGET" -p aivpn-windows; \
	rm -rf "$$PACKAGE_DIR"; \
	mkdir -p "$$PACKAGE_DIR"; \
	cp "$$RELEASE_DIR/aivpn.exe" "$$PACKAGE_DIR/"; \
	cp "$$RELEASE_DIR/aivpn-client.exe" "$$PACKAGE_DIR/"; \
	WINTUN_DLL="$$PACKAGE_DIR/wintun.dll"; \
	if [ ! -f "$$WINTUN_DLL" ]; then \
	    echo "Downloading wintun.dll..."; \
	    WINTUN_ZIP=/tmp/wintun-0.14.1.zip; \
	    [ -f "$$WINTUN_ZIP" ] || curl -L -o "$$WINTUN_ZIP" "https://www.wintun.net/builds/wintun-0.14.1.zip"; \
	    unzip -o "$$WINTUN_ZIP" "wintun/bin/amd64/wintun.dll" -d /tmp/; \
	    cp /tmp/wintun/bin/amd64/wintun.dll "$$WINTUN_DLL"; \
	fi; \
	cp assets/brand/win/aivpn.ico "$$PACKAGE_DIR/aivpn.ico"; \
	if command -v zip >/dev/null 2>&1; then \
	    (cd "$$PACKAGE_DIR" && zip -r "../aivpn-windows-gui.zip" ./*); \
	else \
	    python3 -c "import zipfile,pathlib; pkg=pathlib.Path('$$PACKAGE_DIR'); \
z=zipfile.ZipFile('$$ZIP_NAME','w',zipfile.ZIP_DEFLATED); \
[z.write(f,f.name) for f in pkg.iterdir()]; z.close()"; \
	fi; \
	NSI=crates/aivpn-windows/installer/aivpn-installer.nsi; \
	INSTALLER_EXE=releases/aivpn-windows-installer.exe; \
	if command -v makensis >/dev/null 2>&1 && [ -f "$$NSI" ]; then \
	    echo "Building NSIS installer..."; \
	    makensis -V2 \
	      "-DAPP_VERSION=$(APP_VERSION)" \
	      "-DSTAGE_DIR=$$(pwd)/$$PACKAGE_DIR" \
	      "-DOUTPUT_EXE=$$(pwd)/$$INSTALLER_EXE" \
	      "$$NSI"; \
	    echo "→ $$INSTALLER_EXE  ($$(du -h $$INSTALLER_EXE | cut -f1))"; \
	    rm -rf "$$PACKAGE_DIR"; \
	else \
	    echo "makensis not found — keeping zip: $$ZIP_NAME"; \
	    echo "→ $$ZIP_NAME  ($$(du -h $$ZIP_NAME | cut -f1))"; \
	fi

# ─────────────────────────────────────────────────────────────────────────────
# iOS IPA (macOS + Xcode 15+ required)
# Usage: make ios            — unsigned build
#        make ios TEAM_ID=XX — signed development build
# ─────────────────────────────────────────────────────────────────────────────
ios:
	@set -e; \
	RUSTUP="$$(command -v rustup 2>/dev/null || echo $$HOME/.cargo/bin/rustup)"; \
	[ -x "$$RUSTUP" ] || { echo "ERROR: rustup not found. Install from https://rustup.rs" >&2; exit 1; }; \
	"$$RUSTUP" update stable 2>/dev/null || true; \
	"$$RUSTUP" target add --toolchain stable \
	    aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; \
	CARGO="cargo"; \
	echo "==> cargo: $$CARGO"; \
	REPO_ROOT="$$(pwd)"; \
	IOS_DIR="$$REPO_ROOT/platforms/ios"; \
	CORE_DIR="$$REPO_ROOT/crates/aivpn-ios-core"; \
	TARGET_DIR="$$REPO_ROOT/target"; \
	LIB_DIR="$$CORE_DIR/lib"; \
	CONFIGURATION="$${CONFIGURATION:-Release}"; \
	echo "==> Building Rust core for aarch64-apple-ios (device) ..."; \
	"$$CARGO" build --release -p aivpn-ios-core --target aarch64-apple-ios; \
	echo "==> Building Rust core for aarch64-apple-ios-sim ..."; \
	"$$CARGO" build --release -p aivpn-ios-core --target aarch64-apple-ios-sim; \
	echo "==> Building Rust core for x86_64-apple-ios ..."; \
	"$$CARGO" build --release -p aivpn-ios-core --target x86_64-apple-ios; \
	mkdir -p "$$LIB_DIR"; \
	DEVICE_LIB="$$TARGET_DIR/aarch64-apple-ios/release/libaivpn_core.a"; \
	SIM_ARM_LIB="$$TARGET_DIR/aarch64-apple-ios-sim/release/libaivpn_core.a"; \
	SIM_X86_LIB="$$TARGET_DIR/x86_64-apple-ios/release/libaivpn_core.a"; \
	SIM_FAT="$$LIB_DIR/libaivpn_core_sim.a"; \
	echo "==> Lipo: universal simulator lib ..."; \
	lipo -create "$$SIM_ARM_LIB" "$$SIM_X86_LIB" -output "$$SIM_FAT"; \
	echo "==> Creating XCFramework ..."; \
	mkdir -p "$$CORE_DIR/include"; \
	XCFW="$$LIB_DIR/AivpnCore.xcframework"; \
	rm -rf "$$XCFW"; \
	xcodebuild -create-xcframework \
	    -library "$$DEVICE_LIB" -headers "$$CORE_DIR/include" \
	    -library "$$SIM_FAT"    -headers "$$CORE_DIR/include" \
	    -output "$$XCFW"; \
	cp "$$DEVICE_LIB" "$$LIB_DIR/libaivpn_core.a"; \
	echo "==> Generating Xcode project ..."; \
	cd "$$IOS_DIR" && xcodegen generate --spec project.yml; \
	ARCHIVE="$$IOS_DIR/build/Aivpn.xcarchive"; \
	mkdir -p "$$IOS_DIR/build"; \
	if [ -n "$(TEAM_ID)" ]; then \
	    SIGN_ARGS="DEVELOPMENT_TEAM=$(TEAM_ID) CODE_SIGN_STYLE=Automatic"; \
	else \
	    SIGN_ARGS="CODE_SIGN_IDENTITY=- CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO"; \
	fi; \
	echo "==> Archiving ($$CONFIGURATION) ..."; \
	cd "$$IOS_DIR" && xcodebuild archive \
	    -project Aivpn.xcodeproj -scheme Aivpn \
	    -configuration "$$CONFIGURATION" \
	    -destination "generic/platform=iOS" \
	    -archivePath "$$ARCHIVE" \
	    -allowProvisioningUpdates \
	    $$SIGN_ARGS SKIP_INSTALL=NO BUILD_LIBRARY_FOR_DISTRIBUTION=NO; \
	mkdir -p "$$REPO_ROOT/releases"; \
	DEST="$$REPO_ROOT/releases/aivpn-ios.ipa"; \
	if [ -n "$(TEAM_ID)" ]; then \
	    OPTS="$$IOS_DIR/build/ExportOptions.plist"; \
	    printf '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>method</key><string>development</string><key>teamID</key><string>%s</string><key>compileBitcode</key><false/></dict></plist>' "$(TEAM_ID)" > "$$OPTS"; \
	    cd "$$IOS_DIR" && xcodebuild -exportArchive \
	        -archivePath "$$ARCHIVE" \
	        -exportPath "$$IOS_DIR/build/export" \
	        -exportOptionsPlist "$$OPTS"; \
	    IPA_SRC="$$(find "$$IOS_DIR/build/export" -name '*.ipa' | head -1)"; \
	    [ -n "$$IPA_SRC" ] || { echo "ERROR: .ipa not found" >&2; exit 1; }; \
	    cp "$$IPA_SRC" "$$DEST"; \
	else \
	    APP_PATH="$$(find "$$ARCHIVE/Products" -name '*.app' | head -1)"; \
	    [ -n "$$APP_PATH" ] || { echo "ERROR: .app not found in archive" >&2; exit 1; }; \
	    PAYLOAD="$$IOS_DIR/build/Payload"; \
	    rm -rf "$$PAYLOAD"; mkdir -p "$$PAYLOAD"; \
	    cp -r "$$APP_PATH" "$$PAYLOAD/"; \
	    (cd "$$IOS_DIR/build" && zip -qr "$$DEST" Payload); \
	    rm -rf "$$PAYLOAD"; \
	fi; \
	echo "→ $$DEST  ($$(du -sh $$DEST | cut -f1))"

# ─────────────────────────────────────────────────────────────────────────────
# macOS .app + .pkg + .dmg (macOS only)
# Requires: swiftc, lipo, codesign, pkgbuild, hdiutil (all included with Xcode CLT)
# ─────────────────────────────────────────────────────────────────────────────
macos:
	@echo "==> Building aivpn-client for macOS Universal Binary..."
	@if command -v rustup >/dev/null 2>&1 || [ -x "$$HOME/.cargo/bin/rustup" ]; then \
	    RUSTUP="$$(command -v rustup 2>/dev/null || echo $$HOME/.cargo/bin/rustup)"; \
	    "$$RUSTUP" update stable 2>/dev/null || true; \
	    "$$RUSTUP" target add aarch64-apple-darwin x86_64-apple-darwin 2>/dev/null || true; \
	fi
	cargo build --release -p aivpn-client --features ssh-install --target aarch64-apple-darwin
	cargo build --release -p aivpn-client --features ssh-install --target x86_64-apple-darwin
	@echo "==> Generating ICNS icon from brand source..."
	@python3 platforms/macos/generate_icon.py 2>/dev/null || true
	@echo "==> Building macOS app bundle (swiftc + universal + PKG + DMG)..."
	@bash platforms/macos/build.sh
	@echo "→ releases/aivpn-macos.pkg"
	@echo "→ releases/aivpn-macos.dmg"

# ─────────────────────────────────────────────────────────────────────────────
# Linux GUI binary (no extra tools required)
# ─────────────────────────────────────────────────────────────────────────────
linux: releases/
	cargo build --release -p aivpn-linux
	cargo build --release -p aivpn-client --features ssh-install --bin aivpn-client --bin aivpn-ip-helper
	cp target/release/aivpn-linux      releases/aivpn-linux-x86_64
	cp target/release/aivpn-client     releases/aivpn-client-linux-x86_64
	cp target/release/aivpn-ip-helper  releases/aivpn-ip-helper-linux-x86_64
	chmod +x releases/aivpn-linux-x86_64 releases/aivpn-client-linux-x86_64 releases/aivpn-ip-helper-linux-x86_64
	@echo "→ releases/aivpn-linux-x86_64  ($$(du -h releases/aivpn-linux-x86_64 | cut -f1))"

# ─────────────────────────────────────────────────────────────────────────────
# Linux AppImage
# Requires: appimagetool (https://github.com/AppImage/AppImageKit/releases)
# ─────────────────────────────────────────────────────────────────────────────
linux-appimage:
	@set -e; \
	ARCH=$${ARCH:-x86_64}; \
	APPDIR=AppDir-aivpn-linux; \
	echo "==> Building aivpn-linux release binary..."; \
	cargo build --release -p aivpn-linux; \
	echo "==> Building aivpn-client + aivpn-ip-helper release binaries..."; \
	cargo build --release -p aivpn-client --features ssh-install --bin aivpn-client --bin aivpn-ip-helper; \
	echo "==> Setting up AppDir..."; \
	rm -rf "$$APPDIR"; \
	mkdir -p "$$APPDIR/usr/bin" "$$APPDIR/usr/share/applications" \
	         "$$APPDIR/usr/share/icons/hicolor/256x256/apps"; \
	cp target/release/aivpn-linux     "$$APPDIR/usr/bin/"; \
	cp target/release/aivpn-client    "$$APPDIR/usr/bin/"; \
	cp target/release/aivpn-ip-helper "$$APPDIR/usr/bin/"; \
	printf '[Desktop Entry]\nName=AIVPN\nComment=AI-powered VPN\nExec=aivpn-linux\nIcon=aivpn\nType=Application\nCategories=Network;\n' \
	    > "$$APPDIR/usr/share/applications/aivpn.desktop"; \
	cp "$$APPDIR/usr/share/applications/aivpn.desktop" "$$APPDIR/"; \
	ICON=assets/brand/icon-1024.png; \
	[ -f "$$ICON" ] || ICON=crates/aivpn-linux/assets/icon.png; \
	if [ -f "$$ICON" ]; then \
	    cp "$$ICON" "$$APPDIR/usr/share/icons/hicolor/256x256/apps/aivpn.png"; \
	    cp "$$ICON" "$$APPDIR/aivpn.png"; \
	else \
	    echo "WARN: no icon found — AppImage will have no icon"; \
	    touch "$$APPDIR/aivpn.png"; \
	fi; \
	printf '#!/bin/sh\nSELF="$$(readlink -f "$$0")"\nHERE="$${SELF%%/*}"\nexport PATH="$${HERE}/usr/bin:$${PATH}"\nexec "$${HERE}/usr/bin/aivpn-linux" "$$@"\n' \
	    > "$$APPDIR/AppRun"; \
	chmod +x "$$APPDIR/AppRun"; \
	echo "==> Packaging AppImage..."; \
	OUTPUT="releases/aivpn-linux-$$ARCH.AppImage"; \
	mkdir -p releases; \
	if [ -n "$${APPIMAGETOOL:-}" ] && command -v "$$APPIMAGETOOL" >/dev/null 2>&1; then \
	    ARCH="$$ARCH" "$$APPIMAGETOOL" "$$APPDIR" "$$OUTPUT"; \
	elif command -v appimagetool >/dev/null 2>&1; then \
	    ARCH="$$ARCH" appimagetool "$$APPDIR" "$$OUTPUT"; \
	else \
	    echo "==> appimagetool not found — fetching a local copy (no system install needed)..."; \
	    TOOL="build/.tools/appimagetool-$$ARCH.AppImage"; \
	    mkdir -p build/.tools; \
	    if [ ! -x "$$TOOL" ]; then \
	        curl -fsSL -o "$$TOOL" "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-$$ARCH.AppImage" \
	            || { echo "ERROR: could not download appimagetool. Install it manually or set APPIMAGETOOL=/path/to/appimagetool." >&2; exit 1; }; \
	        chmod +x "$$TOOL"; \
	    fi; \
	    ARCH="$$ARCH" "$$TOOL" --appimage-extract-and-run "$$APPDIR" "$$OUTPUT"; \
	fi; \
	echo "→ $$OUTPUT"

# ─────────────────────────────────────────────────────────────────────────────
# Deploy server to VPS via Docker (downloads prebuilt binary from GitHub)
# Env: AIVPN_REPO_SLUG, AIVPN_RELEASE_TAG (default: latest), AIVPN_SKIP_DOWNLOAD
# ─────────────────────────────────────────────────────────────────────────────
deploy:
	@set -e; \
	REPO_SLUG=$${AIVPN_REPO_SLUG:-infosave2007/aivpn}; \
	RELEASE_TAG=$${AIVPN_RELEASE_TAG:-latest}; \
	SKIP_DL=$${AIVPN_SKIP_DOWNLOAD:-0}; \
	ASSET=aivpn-server-linux-x86_64; \
	ARTIFACT=releases/$$ASSET; \
	mkdir -p releases deploy/config masks; \
	if [ -d assets/masks ]; then \
	    for f in assets/masks/*.json; do \
	        [ -f "$$f" ] || continue; \
	        base="$$(basename $$f)"; \
	        [ -f "masks/$$base" ] || { cp "$$f" "masks/$$base"; echo "Seeded mask: $$base"; }; \
	    done; \
	fi; \
	[ -f deploy/config/server.json ] || cp deploy/config/server.json.example deploy/config/server.json; \
	if [ ! -f deploy/config/server.key ]; then \
	    command -v openssl >/dev/null 2>&1 || { echo "ERROR: openssl required" >&2; exit 1; }; \
	    echo "Generating config/server.key"; \
	    openssl rand 32 > deploy/config/server.key; chmod 600 deploy/config/server.key; \
	fi; \
	SUMS_ASSET=$$ASSET.SHA256SUMS; \
	SUMS_ARTIFACT=releases/$$SUMS_ASSET; \
	if [ "$$SKIP_DL" = "1" ]; then \
	    [ -x "$$ARTIFACT" ] || { echo "ERROR: SKIP_DOWNLOAD=1 but $$ARTIFACT not found" >&2; exit 1; }; \
	    echo "NOTE: SKIP_DOWNLOAD=1 — no published checksum for a locally-built binary; skipping verification."; \
	elif [ "$$RELEASE_TAG" = "latest" ]; then \
	    echo "Downloading $$ASSET (latest)..."; \
	    curl -fL "https://github.com/$$REPO_SLUG/releases/latest/download/$$ASSET" -o "$$ARTIFACT"; \
	    echo "Downloading $$SUMS_ASSET (latest)..."; \
	    curl -fL "https://github.com/$$REPO_SLUG/releases/latest/download/$$SUMS_ASSET" -o "$$SUMS_ARTIFACT" || { \
	        echo "ERROR: could not download $$SUMS_ASSET — refusing to run an unverified binary." >&2; \
	        rm -f "$$ARTIFACT"; exit 1; }; \
	    ( cd releases && sha256sum -c "$$SUMS_ASSET" ) || { \
	        echo "ERROR: checksum verification FAILED for $$ASSET" >&2; exit 1; }; \
	    echo "Checksum verified: $$ASSET"; \
	else \
	    echo "Downloading $$ASSET ($$RELEASE_TAG)..."; \
	    REL_JSON=$$(curl -fsSL "https://api.github.com/repos/$$REPO_SLUG/releases/tags/$$RELEASE_TAG"); \
	    DL_URL=$$(echo "$$REL_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); \
[print(a['browser_download_url']) for a in d.get('assets',[]) if a['name']=='$$ASSET']" | head -1); \
	    SUMS_URL=$$(echo "$$REL_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); \
[print(a['browser_download_url']) for a in d.get('assets',[]) if a['name']=='$$SUMS_ASSET']" | head -1); \
	    [ -n "$$DL_URL" ] || { echo "ERROR: asset not found in release $$RELEASE_TAG" >&2; exit 1; }; \
	    [ -n "$$SUMS_URL" ] || { echo "ERROR: $$SUMS_ASSET not found in release $$RELEASE_TAG — refusing to run an unverified binary." >&2; exit 1; }; \
	    curl -fL "$$DL_URL" -o "$$ARTIFACT"; \
	    curl -fL "$$SUMS_URL" -o "$$SUMS_ARTIFACT"; \
	    ( cd releases && sha256sum -c "$$SUMS_ASSET" ) || { \
	        echo "ERROR: checksum verification FAILED for $$ASSET" >&2; exit 1; }; \
	    echo "Checksum verified: $$ASSET"; \
	fi; \
	chmod +x "$$ARTIFACT"; \
	echo "Enabling IPv4 forwarding..."; \
	RUN="$$([ "$$(id -u)" -eq 0 ] && echo '' || echo sudo)"; \
	$$RUN sysctl -w net.ipv4.ip_forward=1 >/dev/null; \
	DEFAULT_IFACE="$$(ip route show default 2>/dev/null | awk '/default/{print $$5; exit}')"; \
	VPN_CIDR=$$(python3 -c " \
import json,ipaddress; d=json.load(open('deploy/config/server.json')); \
n=d.get('network_config'); \
sip=n['server_vpn_ip'] if n else d.get('tun_addr','10.0.0.1'); \
pl=int(n['prefix_len']) if n else ipaddress.IPv4Network('0.0.0.0/'+d.get('tun_netmask','255.255.255.0')).prefixlen; \
print(ipaddress.IPv4Network(f'{sip}/{pl}',strict=False).with_prefixlen)" 2>/dev/null || echo "10.0.0.0/24"); \
	if [ -n "$$DEFAULT_IFACE" ]; then \
	    $$RUN iptables -t nat -C POSTROUTING -s "$$VPN_CIDR" -o "$$DEFAULT_IFACE" -j MASQUERADE >/dev/null 2>&1 || \
	    $$RUN iptables -t nat -A POSTROUTING -s "$$VPN_CIDR" -o "$$DEFAULT_IFACE" -j MASQUERADE; \
	fi; \
	command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'active' && \
	    $$RUN ufw allow 443/udp >/dev/null || true; \
	echo "Starting server via Docker Compose..."; \
	if docker compose version >/dev/null 2>&1; then DC="docker compose"; else DC="docker-compose"; fi; \
	AIVPN_SERVER_DOCKERFILE=deploy/docker/Dockerfile.prebuilt $$DC up -d --build --force-recreate aivpn-server; \
	echo "Server deployed."; \
	echo "Manage clients: docker compose exec aivpn-server aivpn-server --help"

# Usage:
#   make server-deploy HOST=vps.example.com                     (key-based auth — preferred)
#   make server-deploy HOST=vps.example.com SSH_PASS_FILE=~/.aivpn-pass  (password from a file, needs sshpass)
#   make server-deploy HOST=vps.example.com SSH_PASS=xx          (password inline — DISCOURAGED: leaks
#                                                                   into shell history and `ps` output
#                                                                   for the life of this recipe; prefer
#                                                                   SSH_PASS_FILE or key auth instead)
#   make server-deploy HOST=vps.example.com USER=ubuntu SSH_OPTS="-p 2222"
# ─────────────────────────────────────────────────────────────────────────────
server-deploy:
	@[ -n "$(HOST)" ] || { \
	    printf "ERROR: HOST is required.\nUsage: make server-deploy HOST=vps.example.com [USER=root] [SSH_PASS_FILE=path]\n" >&2; \
	    exit 1; }
	@[ -f releases/aivpn-server-linux-x86_64 ] || { \
	    echo "ERROR: releases/aivpn-server-linux-x86_64 not found. Run 'make server' or 'make server-docker' first." >&2; \
	    exit 1; }
	@set -e; \
	if [ -n "$(SSH_PASS_FILE)" ]; then \
	    [ -f "$(SSH_PASS_FILE)" ] || { echo "ERROR: SSH_PASS_FILE '$(SSH_PASS_FILE)' not found" >&2; exit 1; }; \
	    command -v sshpass >/dev/null 2>&1 || { echo "ERROR: SSH_PASS_FILE requires sshpass (apt install sshpass)" >&2; exit 1; }; \
	    SSH_PFX="sshpass -f '$(SSH_PASS_FILE)'"; \
	    PASS_AUTH=1; \
	elif [ -n "$(SSH_PASS)" ]; then \
	    echo "WARNING: SSH_PASS on the command line is visible in shell history and to other" >&2; \
	    echo "         local users via 'ps' while this recipe runs. Prefer SSH_PASS_FILE=<path>" >&2; \
	    echo "         (chmod 600 file with just the password) or key-based auth instead." >&2; \
	    command -v sshpass >/dev/null 2>&1 || { echo "ERROR: SSH_PASS requires sshpass (apt install sshpass)" >&2; exit 1; }; \
	    SSH_PFX="SSHPASS='$(SSH_PASS)' sshpass -e"; \
	    PASS_AUTH=1; \
	else \
	    SSH_PFX=""; \
	    PASS_AUTH=0; \
	fi; \
	SSHOPTS="$(SSH_OPTS) -o StrictHostKeyChecking=accept-new -o BatchMode=$$([ "$$PASS_AUTH" = 1 ] && echo no || echo yes)"; \
	R="$(RUSER)@$(HOST)"; \
	SSH="$$SSH_PFX ssh $$SSHOPTS $$R"; \
	SCP="$$SSH_PFX scp $$SSHOPTS"; \
	echo "==> Creating remote directories on $(HOST)..."; \
	eval "$$SSH" "mkdir -p $(REMOTE)/releases $(REMOTE)/deploy/config $(REMOTE)/deploy/docker $(REMOTE)/masks"; \
	echo "==> Computing local checksum..."; \
	LOCAL_SHA=$$(sha256sum releases/aivpn-server-linux-x86_64 | awk '{print $$1}'); \
	echo "==> Uploading server binary..."; \
	eval "$$SCP" "releases/aivpn-server-linux-x86_64" "$$R:$(REMOTE)/releases/"; \
	echo "==> Verifying transferred binary integrity (sha256sum -c)..."; \
	REMOTE_SHA=$$(eval "$$SSH" "sha256sum $(REMOTE)/releases/aivpn-server-linux-x86_64" | awk '{print $$1}'); \
	if [ "$$LOCAL_SHA" != "$$REMOTE_SHA" ]; then \
	    echo "ERROR: checksum mismatch after transfer (local=$$LOCAL_SHA remote=$$REMOTE_SHA)." >&2; \
	    echo "       Refusing to build/run the remote binary." >&2; \
	    exit 1; \
	fi; \
	echo "Checksum verified: $$LOCAL_SHA"; \
	echo "==> Uploading Docker files..."; \
	eval "$$SCP" "docker-compose.yml" "$$R:$(REMOTE)/"; \
	eval "$$SCP" "deploy/docker/Dockerfile.prebuilt" "deploy/docker/docker-entrypoint.sh" "$$R:$(REMOTE)/deploy/docker/"; \
	if [ -f deploy/config/server.json ]; then \
	    echo "==> Uploading config..."; \
	    eval "$$SCP" "deploy/config/server.json" "$$R:$(REMOTE)/deploy/config/"; \
	fi; \
	echo "==> Installing Docker on remote (if needed)..."; \
	eval "$$SSH" "export DEBIAN_FRONTEND=noninteractive && \
	    apt-get update -y -qq && \
	    (apt-get install -y docker.io docker-compose-plugin iptables iproute2 ca-certificates curl openssl 2>/dev/null || \
	     apt-get install -y docker.io docker-compose iptables iproute2 ca-certificates curl openssl) && \
	    systemctl enable docker && systemctl start docker"; \
	echo "==> Generating server key if missing..."; \
	eval "$$SSH" "test -f $(REMOTE)/deploy/config/server.key || { openssl rand 32 > $(REMOTE)/deploy/config/server.key && chmod 600 $(REMOTE)/deploy/config/server.key; }"; \
	echo "==> Starting server via Docker Compose..."; \
	eval "$$SSH" "cd $(REMOTE) && \
	    if docker compose version >/dev/null 2>&1; then DC='docker compose'; else DC='docker-compose'; fi && \
	    AIVPN_SERVER_DOCKERFILE=deploy/docker/Dockerfile.prebuilt \$$DC up -d --build --force-recreate aivpn-server"; \
	echo ""; \
	echo "==> Deploy complete. Server running at $(HOST)"

# ─────────────────────────────────────────────────────────────────────────────
# Windows GUI via Docker — no local mingw-w64 required
# Extracts aivpn-client.exe from Docker image into releases/
# ─────────────────────────────────────────────────────────────────────────────
windows-docker: releases/
	@set -e; \
	IMAGE=aivpn-windows-client:build; \
	CTR=aivpn-windows-$$RANDOM; \
	docker build -t $$IMAGE -f deploy/docker/Dockerfile.windows-client .; \
	docker create --name $$CTR $$IMAGE >/dev/null; \
	trap "docker rm -f $$CTR >/dev/null 2>&1 || true" EXIT; \
	docker cp $$CTR:/aivpn-client.exe releases/aivpn-client.exe; \
	echo "→ releases/aivpn-client.exe  ($$(du -h releases/aivpn-client.exe | cut -f1))"

# ─────────────────────────────────────────────────────────────────────────────
# Integration test: server + client in Docker bridge network
# ─────────────────────────────────────────────────────────────────────────────
# Pass AIVPN_TEST_KEY=aivpn://... to give the test client a real connection
# key; without it the client exits immediately and the test fails loudly
# (instead of passing vacuously with an unconfigured client).
test-docker:
	@[ -n "$(AIVPN_TEST_KEY)" ] || \
	    echo "NOTE: AIVPN_TEST_KEY not set — test client has no connection key (run: make test-docker AIVPN_TEST_KEY=aivpn://...)"
	AIVPN_TEST_KEY="$(AIVPN_TEST_KEY)" docker compose -f deploy/docker/docker-compose.test.yml up --build --abort-on-container-exit
	docker compose -f deploy/docker/docker-compose.test.yml down

# ─────────────────────────────────────────────────────────────────────────────
# Linux kernel module (requires kernel headers ≥ 6.1)
# Usage:
#   make kernel              → build .ko in platforms/linux-kernel/
#   make kernel KVER=6.6.0  → target a specific kernel
#   make kernel-install      → install + depmod (root)
# ─────────────────────────────────────────────────────────────────────────────
kernel:
	@echo "==> Building aivpn-linux-kernel module (kernel: $$(uname -r))..."
	$(MAKE) -C platforms/linux-kernel
	@echo "→ platforms/linux-kernel/aivpn.ko"

kernel-install: kernel
	@echo "==> Installing kernel module..."
	$(MAKE) -C platforms/linux-kernel install
	@echo "→ module installed, depmod done"

# ─────────────────────────────────────────────────────────────────────────────
# MikroTik RouterOS container image
# Usage:
#   make mikrotik                                      → push infosave2007/aivpn-mikrotik:latest
#   make mikrotik IMAGE=myrepo/aivpn-mikrotik:v1.0    → custom tag
#   make mikrotik-local                               → arm64 image locally, no push
# ─────────────────────────────────────────────────────────────────────────────
mikrotik:
	@echo "==> Building multi-arch MikroTik images and pushing manifest..."
	bash platforms/mikrotik/build-mikrotik.sh "$(IMAGE)"

mikrotik-local:
	@echo "==> Building local arm64 MikroTik image (no push)..."
	docker build \
	  --platform linux/arm64 \
	  --build-arg MUSL_IMAGE_TAG=aarch64-musl \
	  --build-arg TARGET_TRIPLE=aarch64-unknown-linux-musl \
	  -t aivpn-mikrotik:local \
	  -f platforms/mikrotik/Dockerfile .
	@echo "→ aivpn-mikrotik:local (aarch64)"

# ─────────────────────────────────────────────────────────────────────────────
# OpenWrt — build musl client binaries for common router architectures
# The OpenWrt package Makefile (platforms/openwrt/package/aivpn/Makefile) must
# be built inside the OpenWrt build system or SDK. This target compiles the
# standalone musl client binaries that can be packaged into an ipk manually.
# ─────────────────────────────────────────────────────────────────────────────
openwrt: releases/
	@echo "==> Building OpenWrt client binaries (musl static)..."
	$(MAKE) client-musl-armv7
	$(MAKE) client-musl-mipsel
	$(MAKE) client-musl-aarch64
	@echo ""
	@echo "→ releases/aivpn-client-linux-armv7-musleabihf  (ARMv7 routers)"
	@echo "→ releases/aivpn-client-linux-mipsel-musl       (MIPS routers)"
	@echo "→ releases/aivpn-client-linux-aarch64-musl      (AArch64 routers)"
	@echo ""
	@echo "Package with the OpenWrt SDK: copy platforms/openwrt/package/aivpn/ into"
	@echo "  <sdk>/package/feeds/packages/aivpn and run: make package/aivpn/compile"

# ─────────────────────────────────────────────────────────────────────────────
# Android APK
# Requires: ANDROID_SDK_ROOT, ANDROID_NDK_ROOT env vars (or /opt/android-sdk)
# ─────────────────────────────────────────────────────────────────────────────
android:
	@set -e; \
	SDK_ROOT=$${ANDROID_SDK_ROOT:-/opt/android-sdk}; \
	NDK_ROOT=$${ANDROID_NDK_ROOT:-/opt/android-ndk}; \
	[ -d "$$SDK_ROOT" ] || { echo "ERROR: Android SDK not found at $$SDK_ROOT" >&2; \
	    echo "       Set ANDROID_SDK_ROOT env var or install to /opt/android-sdk" >&2; exit 1; }; \
	[ -d "$$NDK_ROOT" ] || { echo "ERROR: Android NDK not found at $$NDK_ROOT" >&2; \
	    echo "       Set ANDROID_NDK_ROOT env var or install to /opt/android-ndk" >&2; exit 1; }; \
	export ANDROID_SDK_ROOT="$$SDK_ROOT"; \
	export ANDROID_NDK_ROOT="$$NDK_ROOT"; \
	echo "SDK: $$SDK_ROOT"; \
	echo "NDK: $$NDK_ROOT"; \
	echo "sdk.dir=$$SDK_ROOT" > platforms/android/local.properties; \
	echo "==> Building Android APK (release)..."; \
	(cd platforms/android && bash build-rust-android.sh release); \
	if [ -f releases/aivpn-client.apk ]; then \
	    mv releases/aivpn-client.apk releases/aivpn-android.apk; \
	    echo "→ releases/aivpn-android.apk  ($$(du -h releases/aivpn-android.apk | cut -f1))"; \
	else \
	    echo "ERROR: APK not found at releases/aivpn-client.apk"; exit 1; \
	fi

# ─────────────────────────────────────────────────────────────────────────────
# Web management panel (Hono 4 + SvelteKit 2 + Svelte 5)
# Requires: Bun (installed automatically if absent)
# ─────────────────────────────────────────────────────────────────────────────
web:
	@set -e; \
	if ! command -v bun >/dev/null 2>&1; then \
	    echo "==> Installing Bun..."; \
	    curl -fsSL https://bun.sh/install | bash; \
	    export PATH="$$HOME/.bun/bin:$$PATH"; \
	fi; \
	echo "==> Installing web dependencies..."; \
	bun install --frozen-lockfile --cwd platforms/aivpn-web; \
	echo "==> Building aivpn-web..."; \
	bun run --cwd platforms/aivpn-web build; \
	echo "→ platforms/aivpn-web/dist/"; \
	echo ""; \
	echo "DEPLOY NOTE: dist/index.js externalizes the @node-rs/argon2 native"; \
	echo "addon — the deploy dir MUST also contain node_modules/ (runtime deps)"; \
	echo "and client/build/ (the SPA), or the bundle fails at startup with"; \
	echo "'Cannot find module @node-rs/argon2' / serves no UI. Recipe:"; \
	echo "  deploy/: dist/index.js + client/build/ + server/package.json"; \
	echo "  cd deploy/ && bun install --production   # materializes node_modules"; \
	echo "  bun dist/index.js"; \
	echo "(the repo's own node_modules is a bun workspace symlink store — not"; \
	echo "shippable as-is). node_modules is platform-specific (native .node"; \
	echo "binary): run the bun install on the TARGET machine's OS/arch."

web-docker:
	@echo "==> Building aivpn-web Docker image..."
	docker build -t aivpn-web:latest -f platforms/aivpn-web/Dockerfile .
	@echo "→ aivpn-web:latest"
	@echo ""
	@echo "Run with:"
	@echo "  docker run -d --name aivpn-web -p 3000:3000 \\"
	@echo "    -v /run/aivpn/api.sock:/run/aivpn/api.sock \\"
	@echo "    aivpn-web:latest"

web-dev:
	@set -e; \
	if ! command -v bun >/dev/null 2>&1; then \
	    echo "==> Installing Bun..."; \
	    curl -fsSL https://bun.sh/install | bash; \
	    export PATH="$$HOME/.bun/bin:$$PATH"; \
	fi; \
	echo "==> Starting aivpn-web dev servers (Hono backend + SvelteKit frontend)..."; \
	bun run --cwd platforms/aivpn-web dev

# ─────────────────────────────────────────────────────────────────────────────
# Clean
# ─────────────────────────────────────────────────────────────────────────────
clean:
	cargo clean
	$(MAKE) -C platforms/linux-kernel clean 2>/dev/null || true

clean-releases:
	rm -rf releases/
