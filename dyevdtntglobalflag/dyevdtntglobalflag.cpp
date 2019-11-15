
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>
#include <list>
#include <fstream>
#include <algorithm>
#include <vector>

// move here:
#include "panda/plugin.h"
#include "panda/rr/rr_log.h"
#include "callstack_instr/prog_point.h"
#include "panda/plog.h"

#include "panda/addr.h"
#include "taint2/label_set.h"
#include "taint2/taint2.h"
#include "taint2/taint2_ext.h"

#include "callstack_instr/callstack_instr.h"
#include "callstack_instr/callstack_instr_ext.h"

#include "utilhelper.h"
#include "winstruct.h"
/*
#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instruction.h>
#include <llvm/Support/InstIterator.h>
#include <llvm/Support/raw_ostream.h>
*/
/*
#include <capstone/capstone.h>

#if defined(TARGET_I386)
#include <capstone/x86.h>
#elif defined(TARGET_ARM)
#include <capstone/arm.h>
#endif
*/
extern "C" {
	bool init_plugin(void *);
	void uninit_plugin(void *);
}

#define G_PLUGIN_NAME "dyevdtntglobalflag"

FILE* gOutputFile = NULL;
target_ulong gTargetAsid = 0;
target_ulong gNtGlobalFlagAddr = 0;

void tbranch_onjump(Addr a, uint64_t size) {
#if defined(TARGET_I386)
	CPUState* cpu = first_cpu;
	target_ulong pc = panda_current_pc(cpu);
	
	if (!userModeAndUserCodeOnly(cpu, pc, gTargetAsid)) {
		return;
	}
	
	// in sample exe, EvasionExe.exe, the pc is the address of instruction
	// AFTER the jump is executed.
	fprintf(gOutputFile, "Hit branch on jump! in pc=%08x\n", (uint32_t)pc);
	fprintf(gOutputFile, "a.typ: %d, a.val: %016lx, size: %lu\n", a.typ, a.val.ma, size);
	
	/*
	if (a.typ == LADDR) { // after consulting sources, seems to be hardcoded to LADDR,
						  // despite setting with make_maddr call!
		
		// the following, taint2_query always return FALSE, somehow.
		// Skip first.
		
		uint32_t num_tainted = 0;
        Addr ao = a;
        for (uint32_t o = 0; o < size; o++) {
            ao.off = o;
            num_tainted += (taint2_query(ao) != 0);
        }
		
		if (num_tainted > 0) {
			// first_cpu is defined in cpu.h
			// since PANDA only supported one cpu, this is enough.
			fprintf(gOutputFile, "X jmp %08x\n", (uint32_t)pc);
		}
		
	}
	*/
#endif
}

int pcbOnVirtMemRead(
CPUState *env, target_ulong pc, 
target_ulong addr, target_ulong size) {
	
#if defined(TARGET_I386)
	
	if (!userModeAndUserCodeOnly(env, pc, gTargetAsid)) {
		return 0;
	}
	
	CPUArchState* arch = reinterpret_cast<CPUArchState*>(env->env_ptr);
	RR_prog_point pp = rr_prog_point();
	
	if (gNtGlobalFlagAddr == 0) {
		target_ulong fs = arch->segs[R_FS].base;
		
		target_ulong peb;
		if (-1 == panda_virtual_memory_read(env, fs + gWindowsOffsets.fs_peb_off, 
		(uint8_t*)&peb, sizeof(peb))) {
			return 0;
		}
		
		gNtGlobalFlagAddr = peb + gWindowsOffsets.peb_ntglobalflag_off;
		fprintf(gOutputFile, "Found NtGlobalFlag address in PEB: %016lx\n", 
				(uint64_t)gNtGlobalFlagAddr);
	}
	
	if (addr == gNtGlobalFlagAddr) {
		// reading NtGlobalFlag
		fprintf(gOutputFile, "%lu R %016lx %016lx %d\n", 
				pp.guest_instr_count, (uint64_t)pc, (uint64_t)addr, (int)size);
		if (!taint2_enabled()) {
			fprintf(gOutputFile, "TAINT IS ENABLED\n");
			taint2_enable_taint();
			taint2_track_taint_state();
		}
		
		hwaddr ngfhwaddr = panda_virt_to_phys(env, addr);
		fprintf(gOutputFile, "phys of %08x is %016lx\n", (uint32_t)addr, ngfhwaddr);
		taint2_label_ram(ngfhwaddr, 1);
	}
	
	return 0; // do nothing.
#endif
	
	return 0;
	
}

int pcbOnTbExec(CPUState* cpu, TranslationBlock* tb) {
	/*
#if defined(TARGET_I386)
	
	target_ulong pc = panda_current_pc(cpu);
	if (!userModeAndUserCodeOnly(cpu, pc, gTargetAsid)) {
		return 0;
	}
	
	// not great, these produce a lot of code that has been modified by
	// QEMU itself, plus a whole lot of taint code. Making it impractical to analyze this code.
	uint32_t masked = (uint32_t)(pc & 0xFFFF);
	if (masked >= 0x1030 && masked <= 0x109D) {
		llvm::Function* pfunc = tb->llvm_function;
		if (pfunc != NULL) {
			for (llvm::inst_iterator II = llvm::inst_begin(pfunc), IE = llvm::inst_end(pfunc) ; 
			II != IE; ++ II) {
				llvm::errs() << *II << "\n";
			}
		}
	}

#endif
	*/
	return 0;
}

bool init_plugin(void* self) {
	
#if defined(TARGET_I386)
	hard_check_os_windows_7_x86();
	
	panda_require("callstack_instr");
    assert (init_callstack_instr_api());
    panda_require("taint2");
    assert (init_taint2_api());
	
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
	gTargetAsid = (target_ulong)(target_asid);
	
	fprintf(stderr, "[INFO] accept g_target_asid=%08lx\n", (uint64_t)gTargetAsid);
	
	gOutputFile = fopen(G_PLUGIN_NAME ".result.log", "w");
    if(!gOutputFile) return false;
	
	if (!initvars()) return false;
	
	// Need this to get EIP with our callbacks
    panda_enable_precise_pc();
    // Enable memory logging
    panda_enable_memcb();
	
	panda_cb pcb;
	pcb.virt_mem_before_read = pcbOnVirtMemRead;
	panda_register_callback(self, PANDA_CB_VIRT_MEM_BEFORE_READ, pcb);
	
	//pcb.before_block_exec = pcbOnTbExec;
	//panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
	
	PPP_REG_CB("taint2", on_branch2, tbranch_onjump);
	PPP_REG_CB("taint2", on_indirect_jump, tbranch_onjump);
	
	return true;
	
#endif
	return false;
}

void uninit_plugin(void* self) {
	if (gOutputFile) {
		fflush(gOutputFile);
		fclose(gOutputFile);
	}
}


