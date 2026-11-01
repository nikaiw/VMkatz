BINARY_NAME := vmkatz

TARGET_DIR := target

MUSL_TARGET := x86_64-unknown-linux-musl

SHELL := bash

.PHONY: default
default: release

.PHONY: release
release:
	cargo build --release
	@cp $(TARGET_DIR)/release/$(BINARY_NAME) ./$(BINARY_NAME)
	@echo "[+] Built: ./$(BINARY_NAME) ($$(du -h ./$(BINARY_NAME) | cut -f1))"

.PHONY: release-musl
release-musl:
	RUSTUP_HOME=$(CURDIR)/.rustup cargo build --release --target $(MUSL_TARGET)
	@cp $(TARGET_DIR)/$(MUSL_TARGET)/release/$(BINARY_NAME) ./$(BINARY_NAME)-musl
	@echo "[+] Built: ./$(BINARY_NAME)-musl ($$(du -h ./$(BINARY_NAME)-musl | cut -f1))"

.PHONY: release-minimal
release-minimal:
	cargo build --release --no-default-features --features vmware
	@cp $(TARGET_DIR)/release/$(BINARY_NAME) ./$(BINARY_NAME)-minimal
	@echo "[+] Built: ./$(BINARY_NAME)-minimal ($$(du -h ./$(BINARY_NAME)-minimal | cut -f1))"

.PHONY: debug
debug:
	cargo build
	@echo "[+] Built: $(TARGET_DIR)/debug/$(BINARY_NAME)"

.PHONY: check
check:
	cargo check

.PHONY: clippy
clippy:
	cargo clippy --all-features -- -D warnings
	cargo clippy -- -D warnings

.PHONY: check-features
check-features:
	cargo hack check --each-feature --exclude-no-default-features --exclude-features carve,dump --no-dev-deps
	cargo check --no-default-features --features vmware,carve,dump

.PHONY: doc-check
doc-check:
	RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --document-private-items

.PHONY: deny
deny:
	cargo deny check

.PHONY: machete
machete:
	cargo machete

.PHONY: fmt
fmt:
	cargo fmt

.PHONY: fmt-check
fmt-check:
	cargo fmt -- --check

.PHONY: clean
clean:
	cargo clean
	@rm -f ./$(BINARY_NAME) ./$(BINARY_NAME)-musl ./$(BINARY_NAME)-minimal

.PHONY: install
install: release
	@mkdir -p $(HOME)/.local/bin
	cp ./$(BINARY_NAME) $(HOME)/.local/bin/$(BINARY_NAME)
	@echo "[+] Installed: $(HOME)/.local/bin/$(BINARY_NAME)"

# Mirrors the GitHub CI gates. Not reproducible locally (need mingw/wine) and
# therefore excluded: the Windows-target clippy and the wine test run.
.PHONY: ci
ci: fmt-check clippy check-features doc-check deny machete unit-test

.PHONY: hooks
hooks:
	git config core.hooksPath .githooks
	@echo "[+] pre-commit hook enabled (fmt + clippy). Bypass once: git commit --no-verify"

.PHONY: unit-test
unit-test:
	cargo test --all-features

.PHONY: test-lsass
test-lsass: release
	./$(BINARY_NAME) --format ntlm "/home/user/vmware/Windows 10 x64/Windows 10 x64-Snapshot1.vmsn"

.PHONY: test-sam
test-sam: release
	./$(BINARY_NAME) --format ntlm "/home/user/vm/windows10-clean/windows10-clean.vdi"

.PHONY: test-folder
test-folder: release
	./$(BINARY_NAME) "/home/user/vmware/Windows 10 x64/"

.PHONY: test
test: test-lsass test-sam test-folder

.PHONY: help
help:
	@echo "vmkatz - VM memory forensics credential extractor"
	@echo ""
	@echo "Build targets:"
	@echo "  make              Build release binary (default)"
	@echo "  make release      Build optimized release binary → ./vmkatz"
	@echo "  make release-musl Build static musl binary → ./vmkatz-musl"
	@echo "  make release-minimal  VMware-only minimal binary → ./vmkatz-minimal"
	@echo "  make debug        Build debug binary → target/debug/vmkatz"
	@echo "  make install      Install to ~/.local/bin/"
	@echo "  make clean        Remove build artifacts"
	@echo ""
	@echo "Quality:"
	@echo "  make ci           Run the GitHub CI gates (fmt, clippy, features, rustdoc, deny, machete, tests)"
	@echo "  make check        Run cargo check"
	@echo "  make clippy       Run clippy lints"
	@echo "  make check-features  Check every feature in isolation (needs cargo-hack)"
	@echo "  make doc-check    Build rustdoc, warnings denied"
	@echo "  make deny         Dependency policy: advisories, licences, bans, sources (needs cargo-deny)"
	@echo "  make machete      Find unused dependencies (needs cargo-machete)"
	@echo "  make fmt          Format code"
	@echo "  make fmt-check    Check formatting"
	@echo "  make unit-test    Run unit tests"
	@echo ""
	@echo "Tests:"
	@echo "  make test         Run all integration tests"
	@echo "  make test-lsass   Test LSASS extraction (VMware)"
	@echo "  make test-sam     Test SAM extraction (VBox VDI)"
	@echo "  make test-folder  Test folder discovery (VMware)"
	@echo ""
	@echo "Release profile: strip=true, lto=true, codegen-units=1, panic=abort"
	@echo "Default features: vmware,vbox,qemu,hyperv,sam,ntds.dit,carve,dump"
	@echo "Override: cargo build --release --no-default-features --features vmware,sam"
