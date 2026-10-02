# Segfault build entry points; run `make help` for the list.
SHELL := /bin/bash
ROLE ?= all
IFACE ?= enp0s8
CLANG ?= clang
BPF_OUT := target/bpf
BPF_OBJ := $(BPF_OUT)/segfault.bpf.o
BPF_SRC := $(wildcard bpf/*.c)
BPF_HDR := $(wildcard bpf/*.h)
ARCH := $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/')
MULTIARCH := $(shell gcc -print-multiarch 2>/dev/null)
BPF_CFLAGS := -O2 -g -Wall -Werror -target bpf -D__TARGET_ARCH_$(ARCH) -I/usr/include/$(MULTIARCH) -Ibpf
SH_FILES := $(shell find lab -name '*.sh')
PIN_TEST := /sys/fs/bpf/segfault_verify

.PHONY: help setup net check build bpf rust test verify fmt lint lint-c lint-rust lint-sh clean

help: ## Show targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'

setup: ## Install toolchain (ROLE=target|gen|all|ci)
	sudo bash lab/vm/setup-toolchain.sh $(ROLE)

net: ## Configure lab network (ROLE=target|gen, IFACE=enp0s8)
	sudo bash lab/vm/net-setup.sh $(ROLE) $(IFACE)

check: ## Check lab VM readiness (ROLE=target|gen)
	bash lab/vm/check-lab.sh $(ROLE) $(IFACE)

build: bpf rust ## Build BPF object and Rust binaries

bpf: $(BPF_OBJ) ## Build BPF object

$(BPF_OBJ): $(BPF_SRC) $(BPF_HDR)
	@mkdir -p $(BPF_OUT)
	$(CLANG) $(BPF_CFLAGS) -c bpf/segfault.bpf.c -o $@

rust: ## Build release binaries
	cargo build --release --locked

test: ## Run unit tests
	cargo test --workspace --locked

verify: $(BPF_OBJ) ## Load the BPF object through the kernel verifier
	sudo bpftool prog load $(BPF_OBJ) $(PIN_TEST)
	sudo bpftool prog show pinned $(PIN_TEST)
	sudo rm -f $(PIN_TEST)

fmt: ## Format C and Rust sources
	clang-format -i $(BPF_SRC) $(BPF_HDR)
	cargo fmt --all

lint: lint-c lint-rust lint-sh ## Run every linter

lint-c: ## Check C formatting
	clang-format --dry-run --Werror $(BPF_SRC) $(BPF_HDR)

lint-rust: ## Check Rust formatting and clippy
	cargo fmt --all --check
	cargo clippy --workspace --all-targets --locked -- -D warnings

lint-sh: ## Check shell scripts
	shellcheck $(SH_FILES)

clean: ## Remove build output
	cargo clean
