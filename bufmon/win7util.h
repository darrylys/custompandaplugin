#ifndef WIN7UTIL_H
#define WIN7UTIL_H

#include "panda/plugin.h"
#include "panda/common.h"
#include "panda/rr/rr_log.h"
#include "panda/plugin_plugin.h"

namespace win7 {
	
	target_ulong get_kpcr(CPUState* cpu);
	
	target_ulong get_teb(CPUState* cpu);
	
	target_ulong get_pid(CPUState* cpu);
	
	target_ulong get_tid(CPUState* cpu);
	
}


#endif