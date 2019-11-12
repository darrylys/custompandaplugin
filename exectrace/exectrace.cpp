/* PANDABEGINCOMMENT
 * 
 * Authors:
 * 	Suhandi	suhandi@student.sgu.ac.id
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */

#define __STDC_FORMAT_MACROS

extern "C" {
#include "panda/plog.h"
#include <inttypes.h>
#include <capstone/capstone.h>
#if defined(TARGET_I386)
    #include <capstone/x86.h>
#elif defined(TARGET_ARM)
    #include <capstone/arm.h>
#elif defined(TARGET_PPC)
    #include <capstone/ppc.h>
#endif 
}

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>

#include <iostream>
#include <fstream>
#include <algorithm>
#include <map>
#include <set>
#include <vector>
#include <list>

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"
#include "panda/rr/rr_log.h"
#include "callstack_instr/callstack_instr.h"
#include "callstack_instr/callstack_instr_int_fns.h"

#ifdef ECLIPSE
#include "dbgdefs.h"
#endif

#define G_PLUGIN_NAME "exectrace"

FILE *plugin_log;
target_ulong write_size;
target_ulong g_target_asid;

//For Disassembly Process by Capstone
csh handle;
cs_err cs_open_state;

bool translate_callback(CPUState *cpu, target_ulong pc);
int exec_callback(CPUState *cpu, target_ulong pc);

extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);
}

// We're going to log all user instructions
bool translate_callback(CPUState *cpu, target_ulong pc) {
	return !panda_in_kernel(cpu) && 
			panda_current_asid(cpu) == g_target_asid && 
			pc < 0x10000000;
}

int exec_callback(CPUState *cpu, target_ulong pc) {
#ifdef TARGET_I386
	
	// ignore kernel codes
	if (panda_in_kernel(cpu)) {
		return 0;
	}
	
	// don't care other processes
	if (panda_current_asid(cpu) != g_target_asid) {
		return 0;
	}
	
	// only deals with user code (ignore libraries also!)
	if (pc >= 0x10000000) {
		return 0;
	}
	
	CPUArchState* env = (CPUArchState*)cpu->env_ptr;
	
	// An x86 instruction must always fit in 15 bytes; 
	// this does not make much sense for other architectures, 
	// but is just for
	// testing and debugging
	unsigned char buf[32];
	memset(buf, 0, sizeof(buf));
	assert( -1 != panda_virtual_memory_rw(cpu, pc, buf, 15, 0) );
	
	cs_insn *insn;
	size_t count;
	
	// 050118, ~Darryl
	// cs_open should be called just once, in init_plugin
	// and the opened handle can be reused for disassembly
	//
	// the cs_close is called just once, when the code is finishing
	// up. In panda, call this in uninit_plugin
	
	// just disas one instruction only
	count = cs_disasm(handle, buf, sizeof(buf), pc, 1, &insn);

	if (count > 0) {
		RR_prog_point pp = rr_prog_point();
		size_t j;
		for (j = 0; j < count; j++) {
			fprintf(plugin_log, "%lu\t0x%" PRIx64 ":\t%s\t%s\tEAX:%08lx,EBX:%08lx,ECX:%08lx,EDX:%08lx,EBP:%08lx,ESP:%08lx,ESI:%08lx,EDI:%08lx", 
					pp.guest_instr_count, insn[0].address, insn[0].mnemonic, insn[0].op_str, (uint64_t)env->regs[R_EAX], (uint64_t)env->regs[R_EBX], (uint64_t)env->regs[R_ECX]
					, (uint64_t)env->regs[R_EDX], (uint64_t)env->regs[R_EBP], (uint64_t)env->regs[R_ESP], (uint64_t)env->regs[R_ESI], (uint64_t)env->regs[R_EDI]);
			for (int i=0; i<15; ++i) {
				fprintf(plugin_log, " %02x", buf[i]);
			}
			fprintf(plugin_log, "\n");
			break;
		}
		cs_free(insn, count);
	} else {
		fprintf(plugin_log, "ERROR: Failed to disassemble given code!\n");
	}
	
#endif
    return 1;
}

bool init_plugin(void *self) {
    panda_cb pcb;
    //active=false;
    cs_open_state = CS_ERR_OK;
    
    // Need this to get EIP with our callbacks
    panda_enable_precise_pc();
    // Enable memory logging
    panda_enable_memcb();
    
	panda_arg_list* args = panda_get_args(G_PLUGIN_NAME);
	const char * strAsid = panda_parse_string(args, "asid", NULL);
	if (strAsid == NULL) {
		fprintf(stderr, "[ERROR] unable to proceed, give \"asid\" for monitoring using "
				"list of asid parameter, asid is hex string without 0x\n");
        return false;
	}
	panda_free_args(args);
	
	uint64_t target_asid = 0;
	sscanf(strAsid, "%lx", &target_asid);
	g_target_asid = (target_ulong)(target_asid);
	
	fprintf(stderr, "[INFO] accept g_target_asid=%08lx\n", (uint64_t)g_target_asid);
	
    plugin_log = fopen(G_PLUGIN_NAME ".log", "w");    
    if(!plugin_log) return false;
    
    // 050118, ~Darryl
    // moved from exec_callback.
    cs_open_state = cs_open(CS_ARCH_X86, CS_MODE_32, &handle);
    if (cs_open_state != CS_ERR_OK){
        fprintf(stderr, "[ERROR], unable to open capstone for disassembly!\n");
        return false;
    }
    
    // 050118, ~Darryl
    // set options once.
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
    
    // 050118, ~Darryl
    // remove useless callbacks!
    // the filtering is just on cr3 register and buf.cr3. It can be done only in
    // exec_callback. No need to set active flags or whatever.
    
    
    //pcb.virt_mem_after_write = mem_write_callback;
   // panda_register_callback(self, PANDA_CB_VIRT_MEM_BEFORE_WRITE, pcb);
    //pcb.virt_mem_after_read = mem_read_callback;
    //panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_READ, pcb);
    //pcb.before_block_exec = before_block_callback;
    //panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    pcb.insn_exec = exec_callback;
    panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);
    //pcb.after_block_exec = after_block_callback;
    //panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);
    pcb.insn_translate = translate_callback;
    panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);
    
    return true;
}

void uninit_plugin(void *self) {
    
    // 050118, ~Darryl
    // from exec_callback, move here
    // only close if the open was successful.
    if (cs_open_state == CS_ERR_OK) {
        cs_close(&handle);
    }
    
    if (plugin_log) {
        fflush(plugin_log);
        fclose(plugin_log);
    }
}
