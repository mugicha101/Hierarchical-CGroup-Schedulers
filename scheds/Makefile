ifneq ($(KERNELRELEASE),)

# invoked by kernel build system
# build trace kmod

obj-m += trace/scxtp.o
ccflags-y += -I$(src)/trace

else

TARGETS := scx_jlfp scx_gedf

BUILD := build

CC := gcc
CLANG := clang
BPFTOOL := bpftool

ARCH := x86

CFLAGS := -O2 -g -Wall \
	-MMD -MP \
	-Iinclude \
	-I$(BUILD)

BPF_CFLAGS := -O2 -g \
	-MMD -MP \
	-target bpf \
	-D__TARGET_ARCH_$(ARCH) \
	-mcpu=v3 \
	-Iinclude \
	-I$(BUILD) \
	-I/usr/include/$(shell $(CC) -dumpmachine)

LDLIBS := -lbpf -lelf -lz -lpthread

BINARIES := $(addprefix $(BUILD)/,$(TARGETS))
TRACE_CHECK := $(BUILD)/check_tracing

DEPS := $(addprefix $(BUILD)/,$(addsuffix .d,$(TARGETS))) \
	$(addprefix $(BUILD)/,$(addsuffix .bpf.d,$(TARGETS))) \
	$(TRACE_CHECK).d

all: $(BINARIES) $(TRACE_CHECK)

KDIR ?= /lib/modules/$(shell uname -r)/build

trace-module:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

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

$(TRACE_CHECK): trace/check_tracing.c $(addprefix $(BUILD)/,$(addsuffix .bpf.skel.h,$(TARGETS)))
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)

-include $(DEPS)

clean:
	rm -rf $(BUILD)

.PHONY: all clean trace-module

endif
