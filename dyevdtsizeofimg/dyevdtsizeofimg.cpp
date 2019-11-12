
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

#define G_PLUGIN_NAME "dyevdtsizeofimg"

#include "winstruct.h"

extern "C" {
	bool init_plugin(void *);
	void uninit_plugin(void *);
}

FILE* gOutputFile;
target_ulong gTargetAsid;
target_ulong guestValueSizeOfImageOri;
target_ulong guestAddrSizeOfImage;

bool userModeAndUserCodeOnly(CPUState *cpu, target_ulong pc) {
	return !panda_in_kernel(cpu) && 
			panda_current_asid(cpu) == gTargetAsid && 
			pc < 0x10000000;
}

bool soft_check_os_windows_7_x86() {
	return panda_os_familyno == OS_WINDOWS && panda_os_bits == 32 && 
			0 == strcmp(panda_os_variant, "7");
}

void hard_check_os_windows_7_x86() {
	assert(soft_check_os_windows_7_x86());
}

int pcbOnVirtMemWrite(
CPUState *env, target_ulong pc, 
target_ulong addr, target_ulong size, void *buf) {
	
#if defined(TARGET_I386)
	
	if (!userModeAndUserCodeOnly(env, pc)) {
		return 0;
	}
	
	CPUArchState* arch = reinterpret_cast<CPUArchState*>(env->env_ptr);
	
	if (guestAddrSizeOfImage == 0 && guestValueSizeOfImageOri == 0) {
		// initialize these values
		
		// read the guest addr and its contents in kernel.
		target_ulong fs = arch->segs[R_FS].base;
		fprintf(gOutputFile, "fs: %016lx\n", (uint64_t)fs);
		
		target_ulong addrpeb = 0;
		if (-1 == panda_virtual_memory_read(env, fs + gWindowsOffsets.fs_peb_off, 
		(uint8_t*)&addrpeb, sizeof(addrpeb))) {
			return 0;
		}
		fprintf(gOutputFile, "addrpeb: %016lx\n", (uint64_t)addrpeb);
		
		target_ulong addrPebLdrData = 0;
		if (-1 == panda_virtual_memory_read(env, addrpeb + gWindowsOffsets.peb_pebldrdata_off, 
		(uint8_t*)&addrPebLdrData, sizeof(addrPebLdrData))) {
			return 0;
		}
		fprintf(gOutputFile, "addrPebLdrData: %016lx\n", (uint64_t)addrPebLdrData);
		
		target_ulong addrInLoadOrderModuleList = 0;
		if (-1 == panda_virtual_memory_read(env, addrPebLdrData + gWindowsOffsets.pebldrdata_inloadordermodulelist_off,
		(uint8_t*)&addrInLoadOrderModuleList, sizeof(addrInLoadOrderModuleList))) {
			return 0;
		}
		fprintf(gOutputFile, "addrInLoadOrderModuleList: %016lx\n", (uint64_t)addrInLoadOrderModuleList);
		
		target_ulong sizeOfImage = 0;
		if (-1 == panda_virtual_memory_read(env, addrInLoadOrderModuleList + gWindowsOffsets.ldrdatatableentry_sizeofimage_off,
		(uint8_t*)&sizeOfImage, sizeof(sizeOfImage))) {
			return 0;
		}
		
		guestAddrSizeOfImage = addrInLoadOrderModuleList + gWindowsOffsets.ldrdatatableentry_sizeofimage_off;
		guestValueSizeOfImageOri = sizeOfImage;
		fprintf(gOutputFile, "ORIGINAL %016lx %08x\n", (uint64_t)guestAddrSizeOfImage, 
				(uint32_t)guestValueSizeOfImageOri);
	}
	
	RR_prog_point pp = rr_prog_point();
	
	// compare the addr with saved sizeofimg address
	// if matches, put detection.
	if (addr == guestAddrSizeOfImage) {
		fprintf(gOutputFile, "%lu W %016lx %d %08x\n", pp.guest_instr_count, (uint64_t)guestAddrSizeOfImage,
				(int)size, (uint32_t)(*(target_ulong*)(buf)));
	}
	
#endif
	
	return 0;
}

int pcbOnVirtMemRead(
CPUState *env, target_ulong pc, 
target_ulong addr, target_ulong size) {
	return 0; // do nothing.
}
	

bool init_plugin(void* self) {
	
#if defined(TARGET_I386)
	hard_check_os_windows_7_x86();
	
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
	
	if (!initvars()) {
		return false;
	}
	
	fprintf(gOutputFile, "fs_peb_off: %d\n", (int)gWindowsOffsets.fs_peb_off);
	fprintf(gOutputFile, "ldrdatatableentry_sizeofimage_off: %d\n", (int)gWindowsOffsets.ldrdatatableentry_sizeofimage_off);
	fprintf(gOutputFile, "peb_pebldrdata_off: %d\n", (int)gWindowsOffsets.peb_pebldrdata_off);
	fprintf(gOutputFile, "pebldrdata_inloadordermodulelist_off: %d\n", (int)gWindowsOffsets.pebldrdata_inloadordermodulelist_off);
	
	guestValueSizeOfImageOri = 0;
	guestAddrSizeOfImage = 0;
	
	// Need this to get EIP with our callbacks
    panda_enable_precise_pc();
    // Enable memory logging
    panda_enable_memcb();
	
	panda_cb pcb;
	pcb.virt_mem_before_write = pcbOnVirtMemWrite;
	panda_register_callback(self, PANDA_CB_VIRT_MEM_BEFORE_WRITE, pcb);
	
	pcb.virt_mem_before_read = pcbOnVirtMemRead;
	panda_register_callback(self, PANDA_CB_VIRT_MEM_BEFORE_READ, pcb);
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
