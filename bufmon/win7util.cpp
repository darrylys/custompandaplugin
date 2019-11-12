#include "win7util.h"
#include <assert.h>
#include <stdint.h>

namespace win7 {
	
	const int TIB_W7X86_USED_ENTRY_OFF = 0x18;
	const int PEB_W7X86_PID_OFF = 0x20;
	const int PEB_W7X86_TID_OFF = 0x24;
	
	target_ulong get_kpcr(CPUState* cpu) {
		#if defined(TARGET_I386)
		assert(panda_in_kernel(cpu)); // kpcr only useful for kernel mode.
									  // in user mode, FS register points to TEB
		CPUArchState* arch = reinterpret_cast<CPUArchState*> (cpu->env_ptr);
		return arch->segs[R_FS].base;
		#endif
		assert(false);
		return 0;
	}
	
	target_ulong get_teb(CPUState* cpu) {
		#if defined(TARGET_I386)
		CPUArchState* arch = reinterpret_cast<CPUArchState*> (cpu->env_ptr);
		if (!panda_in_kernel(cpu)) {
			return arch->segs[R_FS].base;
		} else {
			// get kpcr
			target_ulong kpcr = get_kpcr(cpu);
			
			// kpcr begins with TIB
			// the TIB used_self entry actually points to TEB.
			// see: https://www.geoffchappell.com/studies/windows/km/ntoskrnl/structs/kpcr.htm
			target_ulong pp_nt_tib = kpcr + TIB_W7X86_USED_ENTRY_OFF;
			target_ulong p_nt_tib = 0;
			//assert(-1 != panda_virtual_memory_read(cpu, pp_nt_tib, (uint8_t*)(&p_nt_tib), sizeof(p_nt_tib)));
			if (-1 == panda_virtual_memory_read(cpu, pp_nt_tib, (uint8_t*)(&p_nt_tib), sizeof(p_nt_tib))) {
				return 0;
			}
			//assert(p_nt_tib > 0);
			
			return p_nt_tib;
		}
		#endif
		assert(false);
		return 0;
		
	}
	
	target_ulong _get_from_teb_with_off(CPUState* cpu, target_ulong off) {
		#if defined(TARGET_I386)
		//CPUArchState* arch = reinterpret_cast<CPUArchState*> (cpu->env_ptr);
		target_ulong teb = get_teb(cpu);
		if (teb == 0) {
			return 0;
		}
		
		target_ulong data = 0;
		//assert(-1 != panda_virtual_memory_read(cpu, teb + off, (uint8_t*)(&data), sizeof(data)));
		if (-1 ==panda_virtual_memory_read(cpu, teb + off, (uint8_t*)(&data), sizeof(data))) {
			return 0;
		}
		return data;
		#endif
		assert(false);
		return 0;
	}
	
	target_ulong get_pid(CPUState* cpu) {
		#if defined(TARGET_I386)
		return _get_from_teb_with_off(cpu, PEB_W7X86_PID_OFF);
		#endif
		assert(false);
		return 0;
	}
	
	target_ulong get_tid(CPUState* cpu) {
		#if defined(TARGET_I386)
		return _get_from_teb_with_off(cpu, PEB_W7X86_TID_OFF);
		#endif
		assert(false);
		return 0;
	}
	
}
