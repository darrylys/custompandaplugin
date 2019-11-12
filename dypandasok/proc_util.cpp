#include "proc_util.h"

#include <functional>
#include "callstack_instr/callstack_instr.h"
#include "callstack_instr/callstack_instr_ext.h"

#include "osi/osi_types.h"
#include "osi/osi_ext.h"

#include "wintrospection/wintrospection.h"
#include "wintrospection/wintrospection_ext.h"
#include "win7x86intro/win7x86intro_ext.h"
#include "win7objecttypes.h"

#include <assert.h>
#include "miscfunc.h"

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

const uint32_t CURRENT_PROCESS_HANDLE = (uint32_t)(~0);
target_ulong process_handle_to_pid(CPUState* env, target_ulong handle) {
	#ifdef TARGET_I386
	if (soft_check_os_windows_7_x86()) {
		target_ulong pid = 0;
		PTR current_eproc = get_current_proc(env);
		if (handle == CURRENT_PROCESS_HANDLE) {
			pid = ::get_pid(env, current_eproc);
		} else {
			HandleObject* h_process = get_win7_handle_object(env, current_eproc, handle);
			if (h_process != NULL) {
				if (h_process->objType == OBJ_TYPE_Process && h_process->pObj != 0) {
					pid = ::get_pid(env, h_process->pObj);
				}
				free(h_process); // uses malloc in the background
			}
		}
		return pid;
	}
	#endif
	return 0;
}
