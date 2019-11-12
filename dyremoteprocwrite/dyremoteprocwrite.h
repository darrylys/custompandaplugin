#ifndef DYREMOTEPROCWRITE_H
#define DYREMOTEPROCWRITE_H

#include "common_types.h"

//typedef void (* on_call_t)(CPUState *env, target_ulong func);
typedef void (*on_remote_write_t)(CPUState* cpu, rpl_asid_t source_asid, rpl_vaddr_t source_pc,
		rpl_asid_t target_asid, rpl_vaddr_t target_addr, rpl_size_t target_write_size, uint8_t* target_write_bytes);
typedef void (*on_remote_write_ex_t)(REMOTE_WRITE* remote_write);

#endif