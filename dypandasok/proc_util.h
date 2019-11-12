#ifndef PROC_UTIL_H
#define PROC_UTIL_H

#include "panda/plugin.h"
#include "panda/common.h"
#include "panda/rr/rr_log.h"
#include "panda/plugin_plugin.h"

target_ulong get_pid(CPUState* env);
target_ulong get_tid(CPUState* env);
target_ulong process_handle_to_pid(CPUState* env, target_ulong handle);

#endif