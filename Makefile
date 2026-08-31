CLANG ?= clang
BPFTOOL ?= bpftool
CFLAGS := -g -O2 -Wall
INCLUDES := -I. -I/usr/include/$(shell uname -m)-linux-gnu

all: edr_lsm_daemon

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

edr_lsm.bpf.o: edr_lsm.bpf.c vmlinux.h common.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 $(INCLUDES) -c edr_lsm.bpf.c -o edr_lsm.bpf.o

edr_lsm.skel.h: edr_lsm.bpf.o
	$(BPFTOOL) gen skeleton edr_lsm.bpf.o > edr_lsm.skel.h

edr_lsm_daemon: edr_lsm_daemon.c edr_lsm.skel.h common.h
	$(CC) $(CFLAGS) edr_lsm_daemon.c -lbpf -lelf -lz -o edr_lsm_daemon

clean:
	rm -f vmlinux.h edr_lsm.bpf.o edr_lsm.skel.h edr_lsm_daemon
