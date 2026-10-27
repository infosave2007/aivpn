## SPDX-License-Identifier: GPL-2.0

KVER ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KVER)/build
PWD  := $(shell pwd)

# Номер ядра не гарантирует совместимость Rust API. dev.rs проверяет owner
# настоящей miscdevice vtable перед регистрацией; NULL означает отказ загрузки.

# XDP BPF program — compiled with clang targeting BPF, independent of kbuild.
# Best-effort: skipped silently if clang is not installed.
XDP_PROG_SRC    := src/xdp_prog.c
XDP_PROG_OBJ    := src/xdp_prog.o
XDP_INSTALL_DIR := /usr/lib/aivpn
BPF_CFLAGS      := -O2 -target bpf -g -Wall

all: _check_kver xdp
	$(MAKE) -C $(KDIR) M=$(PWD) modules

xdp:
	@if command -v clang >/dev/null 2>&1; then \
		echo "  CC BPF  $(XDP_PROG_OBJ)"; \
		clang $(BPF_CFLAGS) -c $(XDP_PROG_SRC) -o $(XDP_PROG_OBJ); \
	else \
		echo "  SKIP    $(XDP_PROG_OBJ) (clang not found — XDP filter unavailable)"; \
	fi

_check_kver:
	@test -r "$(KDIR)/Makefile" || { \
		echo "ERROR: недоступны kernel headers: $(KDIR)" >&2; exit 1; }
	@grep -qx 'CONFIG_RUST=y' "$(KDIR)/include/config/auto.conf" || { \
		echo "ERROR: нужны kernel headers с CONFIG_RUST=y и совместимый Rust toolchain" >&2; exit 1; }

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f $(XDP_PROG_OBJ)

install: all
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	depmod -a
	@if [ -f "$(XDP_PROG_OBJ)" ]; then \
		install -D -m 0644 $(XDP_PROG_OBJ) $(XDP_INSTALL_DIR)/xdp_prog.o; \
		echo "  INSTALL $(XDP_INSTALL_DIR)/xdp_prog.o"; \
	fi

.PHONY: all _check_kver xdp clean install
