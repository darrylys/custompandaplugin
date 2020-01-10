
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

#include <capstone/capstone.h>

#if defined(TARGET_I386)
#include <capstone/x86.h>
#elif defined(TARGET_ARM)
#include <capstone/arm.h>
#endif

extern "C" {
	bool init_plugin(void *);
	void uninit_plugin(void *);
}

#define G_PLUGIN_NAME "dyevdtnopseq"

csh gCapstoneHandle;
bool gCapstoneOpened;
int gLastInsnNopN;

FILE* gOutputFile = NULL;
target_ulong gTargetAsid = 0;
uint32_t gNopWindowSize = 5;

bool userModeAndUserCodeOnly(CPUState *cpu, target_ulong pc) {
	return !panda_in_kernel(cpu) && 
			panda_current_asid(cpu) == gTargetAsid && 
			pc < 0x10000000;
}

void logCheckNopWindow(uint64_t pc, int nopN, int nopWindowSize) {
	if (nopN >= nopWindowSize) {
		RR_prog_point pp = rr_prog_point();
		fprintf(gOutputFile, "%lu %016lx %u\n", pp.guest_instr_count, pc, nopN);
	}
}

void pcbAfterBlockTranslate(CPUState* cpu, TranslationBlock* tb) {
	
	if (!userModeAndUserCodeOnly(cpu, tb->pc)) {
		return;
	}
	
	target_ulong pc = tb->pc;
	uint16_t size = tb->size;
	
	std::vector<uint8_t> buf(size+10);
	if (-1 == panda_virtual_memory_read(cpu, pc, &buf[0], (int)size)) {
		return;
	}
	
	bool lastInsnIsNop = false;
	int lastConsecNopN = 0;
	uint64_t lastInsnBlockStartPc = 0;
	
	cs_insn* insn;
	uint32_t insn_count = cs_disasm(gCapstoneHandle, &buf[0], size, pc, 0, &insn);
	for (uint32_t i = 0; i < insn_count; ++i) {
		if (strncmp("nop", insn[i].mnemonic, 3) == 0) {
			if (lastInsnIsNop) {
				lastConsecNopN++;
			} else {
				lastInsnBlockStartPc = insn[i].address;
				lastInsnIsNop = true;
				lastConsecNopN = 1;
			}
		} else {
			if (lastInsnBlockStartPc > 0) {
				logCheckNopWindow(lastInsnBlockStartPc, lastConsecNopN, (int)gNopWindowSize);
				lastInsnIsNop = false;
				lastConsecNopN = 0;
			}
		}
	}
	
	if (lastInsnBlockStartPc > 0) {
		logCheckNopWindow(lastInsnBlockStartPc, lastConsecNopN, (int)gNopWindowSize);
	}
	
	cs_free(insn, insn_count);
	
	return;
}

bool soft_check_os_windows_7_x86() {
	return panda_os_familyno == OS_WINDOWS && panda_os_bits == 32 && 0 == strcmp(panda_os_variant, "7");
}

void hard_check_os_windows_7_x86() {
	assert(soft_check_os_windows_7_x86());
}

bool init_plugin(void* pSelf) {
	
#if defined(TARGET_I386)
	
	hard_check_os_windows_7_x86();
	
	panda_arg_list* args = panda_get_args(G_PLUGIN_NAME);
	const char * strAsid = panda_parse_string(args, "asid", NULL);
	if (strAsid == NULL) {
		fprintf(stderr, "[ERROR] unable to proceed, give \"asid\" for monitoring using "
				"list of asid parameter, asid is hex string without 0x\n");
        return false;
	}
	gNopWindowSize = panda_parse_uint32_opt(args, "nopsize", 5, "NOP window size");
	panda_free_args(args);
	
	uint64_t target_asid = 0;
	sscanf(strAsid, "%lx", &target_asid);
	gTargetAsid = (target_ulong)(target_asid);
	
	fprintf(stderr, "[INFO] accept g_target_asid=%08lx\n", (uint64_t)gTargetAsid);
	fprintf(stderr, "[INFO] accept Nop Window Size = %u\n", gNopWindowSize);
	
    gOutputFile = fopen(G_PLUGIN_NAME ".result.log", "w");
    if(!gOutputFile) return false;
	
	gCapstoneOpened = false;
	if (cs_open(CS_ARCH_X86, CS_MODE_32, &gCapstoneHandle) != CS_ERR_OK) {
		fprintf(stderr, "[ERROR] Unable to load capstone library\n");
        return false;
	}
	gCapstoneOpened = true;
	
	// Need this to get EIP with our callbacks
    panda_enable_precise_pc();
    // Enable memory logging
    panda_enable_memcb();
	
	panda_cb pcb;
	
	pcb.after_block_translate = pcbAfterBlockTranslate;
	panda_register_callback(pSelf, PANDA_CB_AFTER_BLOCK_TRANSLATE, pcb);
	
	gLastInsnNopN = 0;
	
	return true;
	
#endif
	
	return false;
}

void uninit_plugin(void* pSelf) {
	if (gCapstoneOpened) {
		cs_close(&gCapstoneHandle);
	}
	
	if (gOutputFile) {
		fflush(gOutputFile);
		fclose(gOutputFile);
	}
}

