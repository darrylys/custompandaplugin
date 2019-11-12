/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

//#define NETBEANS

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include <cstdio>
#include <cstdlib>
#include <vector>

using std::vector;

#ifdef NETBEANS
#include "exec/cpu-all.h"
#endif

#ifdef NETBEANS
typedef uint64_t target_ulong;
#endif

#include "winxphdr.h"
#include "osi_process.h"

#define PTR uint32_t

extern "C" {
    bool init_plugin(void *);
    void uninit_plugin(void *);
    
    int on_after_asid_changed_cb(CPUState *env, target_ulong oldval, target_ulong newval);
}

FILE * g_RootkitLog;

PTR get_dtb(CPUState *env, PTR eproc) {
    PTR dtb;
    panda_virtual_memory_rw(env, eproc+EPROC_DTB_OFF, (uint8_t *)&dtb, sizeof(PTR), false);
    return dtb;
}

bool is_valid_process(CPUState *env, PTR eproc) {
    uint8_t type;
    uint8_t size;
    
    panda_virtual_memory_rw(env, eproc+EPROC_TYPE_OFF, (uint8_t *)&type, 1, false);
    panda_virtual_memory_rw(env, eproc+EPROC_SIZE_OFF, (uint8_t *)&size, 1, false);

    return (type == EPROC_TYPE && size == EPROC_SIZE);
}

PTR get_pid(CPUState *env, PTR eproc) {
    PTR pid;
    panda_virtual_memory_rw(env, eproc+EPROC_PID_OFF, (uint8_t *)&pid, sizeof(PTR), false);
    return pid;
}

PTR get_ppid(CPUState *env, PTR eproc) {
    PTR ppid;
    panda_virtual_memory_rw(env, eproc+EPROC_PPID_OFF, (uint8_t *)&ppid, sizeof(PTR), false);
    return ppid;
}

// *must* be called on a buffer of size 16 or greater
void get_procname(CPUState *env, PTR eproc, char *name) {
    panda_virtual_memory_rw(env, eproc+EPROC_NAME_OFF, (uint8_t *)name, 15, false);
    name[15] = '\0';
}

PTR get_next_proc(CPUState *env, PTR eproc) {
    PTR next;
    if (-1 == panda_virtual_memory_rw(env, eproc+EPROC_LINKS_FLINK_OFF, (uint8_t *)&next, sizeof(PTR), false)) 
        return 0;
    next -= EPROC_LINKS_FLINK_OFF;
    return next;
}

PTR get_prev_proc(CPUState *env, PTR eproc) {
    PTR next;
    if (-1 == panda_virtual_memory_rw(env, eproc+EPROC_LINKS_BLINK_OFF, (uint8_t *)&next, sizeof(PTR), false)) 
        return 0;
    next -= EPROC_LINKS_BLINK_OFF;
    return next;
}

PTR get_kpcr(CPUState *env) {
#if defined(TARGET_I386)
	CPUArchState *arch = reinterpret_cast<CPUArchState*>(env->env_ptr);
    return arch->segs[R_FS].base;
#endif
	return 0;
}

PTR get_current_proc(CPUState *env, PTR kpcr) {
    
    PTR thread, proc, fs_base;
    
    fs_base = kpcr; 
    
    // Read KPCR->CurrentThread->Process
    panda_virtual_memory_rw(env, fs_base+KPCR_CURTHREAD_OFF, (uint8_t *)&thread, sizeof(PTR), false);
    panda_virtual_memory_rw(env, thread+ETHREAD_EPROC_OFF, (uint8_t *)&proc, sizeof(PTR), false);
    
    return proc;
}

void fill_OsiProcess(CPUState *env, PTR eproc, OsiProcess &out) {
    PID pid = get_pid(env, eproc);
    PID ppid = get_ppid(env, eproc);
    
    char name[16];
    get_procname(env, eproc, name);
    
    ADDR asid = get_dtb(env, eproc);
    
    out.asid = asid;
    out.eproc = eproc;
    out.pid = pid;
    out.ppid = ppid;
    out.imageName = string(name);
}

/* Finds the system process from current process
 * System process has PID = 4 in Windows.
 */
bool find_system_process_from_current(CPUState *env, PTR &out) {
    
    PTR kpcr = get_kpcr(env);
    PTR first_eproc = get_current_proc(env, kpcr);
    PTR first_pid = get_pid(env, first_eproc);
    
    if (first_pid == 0) { // idle proc
        return false;
    }
    
    // find PID == 4
    PTR current_eproc = first_eproc;
    PTR current_pid;
    out = 0;
    
    do {
        
        if (is_valid_process(env, current_eproc)) {
            
            current_pid = get_pid(env, current_eproc);
            if (current_pid == 4) {
                out = current_eproc;
                break;
            }
            
        }
        
        current_eproc = get_next_proc(env, current_eproc);
        if (!current_eproc) {
            break;
        }
        
    } while(current_eproc != first_eproc);
    
    return true;
}

bool get_processes_from_startingpoint(CPUState *env, PTR starting_eproc, vector<OsiProcess> &out_processes);

bool get_processes(CPUState *env, vector<OsiProcess> &out_processes) {
    return get_processes_from_startingpoint(env, 0, out_processes);
}

bool get_processes_from_system(CPUState *env, vector<OsiProcess> &out_processes) {
    PTR system_eproc = 0;
    if (find_system_process_from_current(env, system_eproc)) {
        return get_processes_from_startingpoint(env, system_eproc, out_processes);
    }
    return false;
}

bool get_processes_from_startingpoint(CPUState *env, PTR starting_eproc, vector<OsiProcess> &out_processes) {
    
    PTR first_eproc = starting_eproc;
    
    if (!starting_eproc) {
        PTR kpcr = get_kpcr(env);
        first_eproc = get_current_proc(env, kpcr);
        PTR first_pid = get_pid(env, first_eproc);

        if (first_pid == 0) { // idle proc
            return false;
        }
    }
    
    PTR current_eproc = first_eproc;
    do {
        
        if (is_valid_process(env, current_eproc)) {
            
            OsiProcess proc;
            fill_OsiProcess(env, current_eproc, proc);
            out_processes.push_back(proc);
            
        }
        
        current_eproc = get_next_proc(env, current_eproc);
        if (!current_eproc) {
            break;
        }
        
    } while(current_eproc != first_eproc);
    
    return true;
}

//void _get_processes(CPUState *env, OsiProcs **out_ps) {
//    PTR first = get_current_proc(env);
//    PTR first_pid = get_pid(env, first);
//    PTR current = first;
//
//    if (first_pid == 0) { // Idle proc, don't try
//        out_ps = NULL;
//        return;
//    }
//
//    OsiProcs *ps = (OsiProcs *)malloc(sizeof(OsiProcs));
//    ps->num = 0;
//    ps->proc = NULL;
//
//    do {
//        // One of these will be the loop head,
//        // which we don't want to include
//        /*
//            Since I'm using KTHREAD_KPROC_OFF as an ETHREAD, check to make
//            sure this is a kernel thread that has an associated user process.
//        */
//        if (is_valid_process(env, current)) {
//            add_proc(env, ps, current);
//        }
//
//        current = get_next_proc(env, current);
//        if (!current) break;
//    } while (current != first);
//
//    *out_ps = ps;
//}

int on_after_asid_changed_cb(CPUState *env, target_ulong oldval, target_ulong newval) {
    
    PTR kpcr = get_kpcr(env);
    PTR first_eproc = get_current_proc(env, kpcr);
    PTR first_pid = get_pid(env, first_eproc);
    
    if (first_pid == 0) {
        // skip. Idle process
        return 0;
    }
    
    if (is_valid_process(env, first_eproc)) {
    
        //fprintf(g_RootkitLog, "CURRENT PROCESS: \n");
        //OsiProcess curr;
        //fill_OsiProcess(env, first_eproc, curr);
        //dump_OsiProcess(g_RootkitLog, curr);
        
        PTR system_eproc = 0;
        if (!find_system_process_from_current(env, system_eproc)) {
            return 0;
        }
        
        vector<OsiProcess> osi_processes;
        if (system_eproc) {
        
            if (!get_processes_from_system(env, osi_processes)) {
                return 0;
            }

            uint32_t sz = osi_processes.size();
            //fprintf(g_RootkitLog, "PROCESS NUMBER: %u\n", sz);

            for (uint32_t i=0; i<sz; ++i) {
                OsiProcess &proc = osi_processes[i];
                //fprintf(g_RootkitLog, "PROCESS: \n");
                //dump_OsiProcess(g_RootkitLog, proc);

                if (proc.pid == first_pid) {
                    // process found, return
                    return 0;
                }
            }
        }

        fprintf(g_RootkitLog, "Detect EPROCESS hiding\n");
        OsiProcess hidden;
        fill_OsiProcess(env, first_eproc, hidden);
        dump_OsiProcess(g_RootkitLog, hidden);
        
    }
    return 0;
}

bool init_plugin(void *self) {
    g_RootkitLog = NULL;
    
#ifdef TARGET_I386
    g_RootkitLog = fopen("rootkit_detector.log", "w");
    if (g_RootkitLog) {
        // write stuff here
        
        fprintf(g_RootkitLog, "initializing plugin\n");
        
        panda_cb pcb;
        pcb.asid_changed = on_after_asid_changed_cb;
        panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);
        
        
    }
    
    return true;
#endif
    
    return false;
}

void uninit_plugin(void *self) {
    
    if (g_RootkitLog) {
        fprintf(g_RootkitLog, "uninitializing plugin\n");
        fclose(g_RootkitLog);
    }
    
}
