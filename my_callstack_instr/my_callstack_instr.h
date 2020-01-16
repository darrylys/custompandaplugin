#ifndef __CALLSTACK_INSTR_H
#define __CALLSTACK_INSTR_H

#include "my_prog_point.h"

typedef void (* on_call_t)(CPUState *env, target_ulong func);
typedef void (* on_ret_t)(CPUState *env, target_ulong func);

#endif
