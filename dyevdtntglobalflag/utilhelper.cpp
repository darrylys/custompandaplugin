#include "utilhelper.h"

#include "panda/plugin.h"

bool soft_check_os_windows_7_x86() {
	return panda_os_familyno == OS_WINDOWS && panda_os_bits == 32 && 
			0 == strcmp(panda_os_variant, "7");
}

void hard_check_os_windows_7_x86() {
	assert(soft_check_os_windows_7_x86());
}

bool userModeAndUserCodeOnly(CPUState *cpu, target_ulong pc, target_ulong targetAsid) {
	return !panda_in_kernel(cpu) && 
			panda_current_asid(cpu) == targetAsid && 
			pc < 0x10000000;
}

