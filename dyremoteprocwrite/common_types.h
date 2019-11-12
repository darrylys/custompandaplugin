#ifndef COMMONS_TYPES_H
#define COMMONS_TYPES_H

#include <stdint.h>

typedef uint64_t rpl_asid_t;
typedef uint64_t rpl_vaddr_t;
typedef uint64_t rpl_haddr_t;
typedef uint32_t rpl_size_t;
typedef uint32_t rpl_pid_t;
typedef uint32_t rpl_tid_t;

typedef struct _REMOTE_WRITE {
	void* cpu;
	rpl_asid_t source_asid;
	rpl_vaddr_t source_pc;
	rpl_tid_t source_tid;
	rpl_asid_t target_asid;
	rpl_vaddr_t target_addr;
	rpl_size_t target_write_size;
	uint8_t* target_write_bytes;
} REMOTE_WRITE;

#endif