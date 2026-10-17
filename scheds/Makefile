ifneq ($(KERNELRELEASE),)

# invoked by kernel build system
# build trace kmod

obj-m += trace/scxtp.o
ccflags-y += -I$(src)/trace

else

TARGETS := scx_jlfp scx_gedf

BUILD := build

CC := gcc
CLANG := clang-22
BPFTOOL := bpftool
SCXTP_HOTPATH_TRACING ?= 0
SCXTP_LOWFREQ_TRACING ?= 0
SCXTP_OP_TRACING ?= 0
SCXTP_TRACING ?= $(if $(filter 1,$(SCXTP_LOWFREQ_TRACING) $(SCXTP_HOTPATH_TRACING) $(SCXTP_OP_TRACING)),1,0)
SCX_LATENCY_STATS ?= 1

ARCH := x86

CFLAGS := -O2 -g -Wall \
	-MMD -MP \
	-Iinclude \
	-I$(BUILD)

BPF_CFLAGS := -O2 -g \
	-MMD -MP \
	-target bpf \
	-D__TARGET_ARCH_$(ARCH) \
	-DSCXTP_TRACING=$(SCXTP_TRACING) \
	-DSCXTP_LOWFREQ_TRACING=$(SCXTP_LOWFREQ_TRACING) \
	-DSCXTP_HOTPATH_TRACING=$(SCXTP_HOTPATH_TRACING) \
	-DSCXTP_OP_TRACING=$(SCXTP_OP_TRACING) \
	-DSCX_LATENCY_STATS=$(SCX_LATENCY_STATS) \
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
