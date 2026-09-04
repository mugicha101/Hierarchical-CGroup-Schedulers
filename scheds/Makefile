TARGETS := scx_jlfp

BUILD := build

CC := gcc
CLANG := clang
BPFTOOL := bpftool

ARCH := x86

CFLAGS := -O2 -g -Wall \
	-Iinclude \
	-I$(BUILD)

BPF_CFLAGS := -O2 -g \
	-target bpf \
	-D__TARGET_ARCH_$(ARCH) \
	-mcpu=v3 \
	-Iinclude \
	-I$(BUILD) \
	-I/usr/include/$(shell $(CC) -dumpmachine)

LDLIBS := -lbpf -lelf -lz -lpthread

BINARIES := $(addprefix $(BUILD)/,$(TARGETS))

all: $(BINARIES)

$(BUILD):
	mkdir -p $@

$(BUILD)/vmlinux.h: | $(BUILD)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BUILD)/%.bpf.o: %.bpf.c $(BUILD)/vmlinux.h | $(BUILD)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BUILD)/%.bpf.skel.h: $(BUILD)/%.bpf.o
	$(BPFTOOL) gen skeleton $< name $* > $@

$(BUILD)/%: %.c $(BUILD)/%.bpf.skel.h
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)

clean:
	rm -rf $(BUILD)

.PHONY: all clean