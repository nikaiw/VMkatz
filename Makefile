BINARY_NAME := vmkatz
FEATURES ?= vmware,vbox,sam

RELEASE_DIR := release
TARGET_DIR := target

SHELL := bash

.PHONY: default
default: release

.PHONY: release
release:
	cargo build --release --features $(FEATURES)
	@cp $(TARGET_DIR)/release/$(BINARY_NAME) ./$(BINARY_NAME)
	@echo "[+] Built: ./$(BINARY_NAME) ($$(du -h ./$(BINARY_NAME) | cut -f1))"

.PHONY: debug
debug:
	cargo build --features $(FEATURES)
	@echo "[+] Built: $(TARGET_DIR)/debug/$(BINARY_NAME)"

.PHONY: check
check:
	cargo check --features $(FEATURES)

.PHONY: clippy
clippy:
	cargo clippy --features $(FEATURES) -- -D warnings

.PHONY: fmt
fmt:
	cargo fmt

.PHONY: fmt-check
fmt-check:
	cargo fmt -- --check

.PHONY: clean
clean:
	cargo clean
	@rm -f ./$(BINARY_NAME)

.PHONY: strip
strip: release
	strip ./$(BINARY_NAME)
	@echo "[+] Stripped: ./$(BINARY_NAME) ($$(du -h ./$(BINARY_NAME) | cut -f1))"

.PHONY: install
install: release
	@mkdir -p $(HOME)/.local/bin
	cp ./$(BINARY_NAME) $(HOME)/.local/bin/$(BINARY_NAME)
	@echo "[+] Installed: $(HOME)/.local/bin/$(BINARY_NAME)"

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
	@echo "  make debug        Build debug binary → target/debug/vmkatz"
	@echo "  make strip        Build and strip release binary"
	@echo "  make install      Install to ~/.local/bin/"
	@echo "  make clean        Remove build artifacts"
	@echo ""
	@echo "Quality:"
	@echo "  make check        Run cargo check"
	@echo "  make clippy       Run clippy lints"
	@echo "  make fmt          Format code"
	@echo "  make fmt-check    Check formatting"
	@echo ""
	@echo "Tests:"
	@echo "  make test         Run all integration tests"
	@echo "  make test-lsass   Test LSASS extraction (VMware)"
	@echo "  make test-sam     Test SAM extraction (VBox VDI)"
	@echo "  make test-folder  Test folder discovery (VMware)"
	@echo ""
	@echo "Options:"
	@echo "  FEATURES=vmware,vbox,sam  Select features (default: all)"
