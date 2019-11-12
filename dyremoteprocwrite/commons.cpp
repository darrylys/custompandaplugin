#include "commons.h"
#include "winstruct.h"
#include <cstring>
#include <assert.h>

#include <functional>
#include "callstack_instr/callstack_instr.h"
#include "callstack_instr/callstack_instr_ext.h"

#include "osi/osi_types.h"
#include "osi/osi_ext.h"

#include "wintrospection/wintrospection.h"
#include "wintrospection/wintrospection_ext.h"
#include "win7x86intro/win7x86intro_ext.h"
#include "win7objecttypes.h"

#include <vector>
#include <string>
#include <sstream>
#include <cstdio>

void hard_check_os_windows_7_x86() {
	assert(soft_check_os_windows_7_x86());
}

bool soft_check_os_windows_7_x86() {
	return panda_os_familyno == OS_WINDOWS && 
			panda_os_bits == 32 && 
			0 == strcmp(panda_os_variant, "7");
}

target_ulong process_handle_to_pid(CPUState* env, target_ulong handle) {
	target_ulong target_pid = 0;
	PTR current_eproc = get_current_proc(env);
	
	if (handle == CURRENT_PROCESS) {
		target_pid = get_pid(env, current_eproc);
		
	} else {
		HandleObject* h_process = get_win7_handle_object(env, current_eproc, handle);
		if (h_process != NULL) {
			if (h_process->objType == OBJ_TYPE_Process && h_process->pObj != 0) {
				target_pid = get_pid(env, h_process->pObj);
			}
			free(h_process);
		}
	}
	
	return target_pid;
}

/**
* Reads Process ID of current process.
* Only tested on Windows 7 x86 SP1.
*/
target_ulong get_pid(CPUState* env) {
#ifdef TARGET_I386
    CPUArchState *arch = reinterpret_cast<CPUArchState*> (env->env_ptr);
    target_ulong fs = arch->segs[R_FS].base;
    target_ulong fs_pid;
    if (-1 == panda_virtual_memory_read(env, fs + 0x20, (uint8_t*) (&fs_pid), sizeof (fs_pid))) {
		assert(false);
        return 0;
    } else {
        return fs_pid;
    }
#endif
    return 0; // 0 is idle process, which means invalid for our purposes.
}

/**
 * Reads Thread ID of currently running thread.
 * Only tested on Windows 7 x86 SP1.
 */
target_ulong get_tid(CPUState* env) {
#ifdef TARGET_I386
    CPUArchState *arch = reinterpret_cast<CPUArchState*> (env->env_ptr);
    target_ulong fs = arch->segs[R_FS].base;
    target_ulong fs_tid;
    if (-1 == panda_virtual_memory_read(env, fs + 0x24, (uint8_t*) (&fs_tid), sizeof (fs_tid))) {
		assert(false);
        return 0;
    } else {
        return fs_tid;
    }
#endif
    return 0; // 0 is an invalid thread, according to MSDN and Raymond Chen
}

#define MAX_CALLERS (25)
#define DLL_BASE (0x10000000)
target_ulong find_caller_in_process_module(CPUState* env) {
	target_ulong module_pc = panda_current_pc(env);
	target_ulong callers[MAX_CALLERS];
	uint32_t n_callers = ::get_callers(callers, MAX_CALLERS, env);
	for (uint32_t i = 0; i < n_callers; ++i) {
		if (callers[i] < DLL_BASE) {
			module_pc = callers[i];
			break;
		}
	}
	return module_pc;
}

/**
 * Reads zero-terminated wide string (UTF-16LE) from guest
 */
uint32_t guest_wzstrncpy(CPUState *cpu, uint16_t *buf, size_t maxlen, target_ulong guest_addr) {
	buf[0] = 0;
	unsigned i = 0;
	for (i = 0; i < maxlen; i++) {
		panda_virtual_memory_rw(cpu, guest_addr + sizeof (buf[0]) * i, (uint8_t *) & buf[i], sizeof (buf[0]), 0);
		if (buf[i] == 0) {
			break;
		}
	}
	buf[maxlen - 1] = 0;
	return i;
}

/**
 * Reads zero-terminated ascii-string from guest
 */
uint32_t guest_zstrncpy(CPUState *cpu, char *buf, size_t maxlen, target_ulong guest_addr) {
	buf[0] = 0;
	unsigned i = 0;
	for (i = 0; i < maxlen; i++) {
		panda_virtual_memory_rw(cpu, guest_addr + sizeof (buf[0]) * i, (uint8_t *) & buf[i], sizeof (buf[0]), 0);
		if (buf[i] == 0) {
			break;
		}
	}
	buf[maxlen - 1] = 0;
	return i;
}

/**
 * Reads possibly non zero-terminated wide (2 byte) character string from guest.
 * @param cpu
 * @param buf must contain minimum nRead+1 number of characters
 * @param nRead is number of characters read
 * @param guest_addr
 * @return 
 */
uint32_t guest_wbstrncpy(CPUState *cpu, uint16_t *buf, int nRead, target_ulong guest_addr) {
	buf[0] = 0;
	unsigned i = 0;
	for (i = 0; i < nRead; i++) {
		panda_virtual_memory_rw(cpu, guest_addr + sizeof (buf[0]) * i, (uint8_t *) & buf[i], sizeof (buf[0]), 0);
		if (buf[i] == 0) {
			break;
		}
	}
	buf[nRead] = 0;
	return i;
}

/**
 * Reads possibly non zero-terminated single byte character string from guest
 * @param cpu
 * @param buf must contain minimum nRead+1 number of characters
 * @param nRead is number of characters read. 
 * @param guest_addr
 * @return 
 */
uint32_t guest_bstrncpy(CPUState *cpu, char *buf, int nRead, target_ulong guest_addr) {
	buf[0] = 0;
	unsigned i = 0;
	for (i = 0; i < nRead; i++) {
		panda_virtual_memory_rw(cpu, guest_addr + sizeof (buf[0]) * i, (uint8_t *) & buf[i], sizeof (buf[0]), 0);
		if (buf[i] == 0) {
			break;
		}
	}
	buf[nRead] = 0;
	return i;
}

bool is_ascii_printable(uint32_t ch) {
	return ch >= 0x20 && ch <= 0x7e;
}

bool extract_string_from_object_attributes(CPUState* cpu, target_ulong addr, std::string& out) {
	
	OBJECT_ATTRIBUTES obj_attr = {0};
	if (-1 == panda_virtual_memory_read(cpu, addr, (uint8_t*)(&obj_attr), sizeof(obj_attr))) {
		return false;
	}
	
	target_ulong wstr_addr = obj_attr.ObjectName;
	
	UNICODE_STRING wstr = {0};
	if (-1 == panda_virtual_memory_read(cpu, wstr_addr, (uint8_t*)(&wstr), sizeof(wstr))) {
		return false;
	}
	
	std::vector < uint16_t > wstrbuf(wstr.Length/2 + 2); // add sentinel null char space (1) + 1, for precaution.
	
	uint32_t len = guest_wbstrncpy(cpu, &wstrbuf[0], wstr.Length/2, wstr.Buffer);
	std::stringstream ss;
	for (uint32_t i = 0; i < len; ++i) {
		uint16_t wch = wstrbuf[i];
		if (is_ascii_printable(wch)) {
			ss << (char)(wch);
		} else {
			char tmp[8];
			memset(tmp, 0, sizeof(tmp));
			snprintf(tmp, sizeof(tmp)-1, "\\x%x", wch);
			ss << tmp;
		}
	}
	
	out = ss.str();
	return true;
	
}
