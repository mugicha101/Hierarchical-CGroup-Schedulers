// include after vmlinux.h or scx/common.bpf.h
#ifndef TRACE_EVENTS__EVENTS_BPF_H
#define TRACE_EVENTS__EVENTS_BPF_H

#ifndef __BPF__
#error "This file must be compiled for BPF"
#endif

#include "event_types.h"
#include "helpers.h"

SCXTP_EVENT_LIST(SCXTP_DECLARE_KFUNC)

#endif
