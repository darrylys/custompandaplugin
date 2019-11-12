
//#define NETBEANS

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "winhelper.h"

#ifdef NETBEANS
#include "exec/cpu-all.h"
#endif

#include "pandawinpeheader.h"

#include <string>

using std::string;

#ifdef NETBEANS
typedef uint64_t target_ulong;
#endif

#define N__PLUGIN_NAME__ "winxpsp3x86_api_logger"
#define PTR panda::win::ptr_t

typedef uint8_t byte_t;

target_ulong g_pc_prev;
FILE * g_debug_log;
bool g_in_process;
uint32_t g_target_proc_pid;
const char * g_target_proc_name;

extern "C" {
    bool init_plugin(void *);
    void uninit_plugin(void *);
    
    int on_after_asid_changed_cb(CPUState *env, target_ulong oldval, 
            target_ulong newval);
}

bool on_insn_translate_cb(CPUState * state, target_ulong pc) {
#ifdef TARGET_I386
	if (g_in_process) {
		// instrument everything for now
		return true;
    }
    return false;
#else    
    return false;
#endif
}

bool A(target_ulong pc) {
    return pc < 0x70000000;
}

bool L(target_ulong pc) {
    return pc >= 0x70000000 && pc < (uint32_t)0x80000000;
}

bool K(target_ulong pc) {
    return pc >= (uint32_t)0x80000000;
}

void dumpCallAPI(CPUState *env, target_ulong pc, target_ulong prev) {
#ifdef TARGET_I386
    panda::win::ptr_t img_base = panda::win::find_image_base_addr(env, pc);
    if (img_base) {
        winpe::WinPEPanda panda_win(env, img_base, g_debug_log);
        
        string api_name = panda_win.get_api_name_from_addr(pc);
        
        fprintf(g_debug_log, 
        	"img_base 0x%016lx | 0x%016lx --> 0x%016lx | %s\n", 
        	(uint64_t)img_base, 
        	(uint64_t)prev, 
        	(uint64_t)pc, 
        	api_name.c_str());
    }
#endif
}

void dumpReturnAPI(CPUState *env, target_ulong pc, target_ulong prev) {
#ifdef TARGET_I386
    CPUArchState * arch = reinterpret_cast<CPUArchState*>(env->env_ptr);
    target_ulong eax = arch->regs[R_EAX];
    
    // return value should be in eax
    fprintf(g_debug_log, "0x%016lx --> 0x%016lx | (signed=%ld)(unsigned=%lu)(0x%016lx)\n", 
        (uint64_t)prev, 
	    (uint64_t)pc, (int64_t) eax, (uint64_t) eax, (uint64_t) eax);
#endif
}



int on_insn_exec_cb(CPUState *env, target_ulong pc) {
#ifdef TARGET_I386
    
    if (g_in_process) {
		if (g_pc_prev) {
		    
		    if (A(g_pc_prev)) { 
		        if (L(pc) || K(pc)) {
		            dumpCallAPI(env, pc, g_pc_prev);
		        }
		        
		    } else if (L(g_pc_prev)) {
		        
		        if (K(pc)) { // A -- K
		            dumpCallAPI(env, pc, g_pc_prev);
		            
		        } else if (A(pc)) { // A -- L
		            dumpReturnAPI(env, pc, g_pc_prev);
		            
		        }    
		        
		    } else if (K(g_pc_prev)) {
		        if (L(pc) || A(pc)) {
		            dumpReturnAPI(env, pc, g_pc_prev);
		        }
		    }
		    
		}
		
		g_pc_prev = pc;
    }
    //CPUArchState * arch = reinterpret_cast<CPUArchState*>(env->env_ptr);
    //fprintf(g_dbgFile, "PC=%016llx, eax=%016llx\n", (llu)pc, (llu)(arch->regs[R_EAX]));
#else
    
#endif
    
    return 0;
}

int on_after_asid_changed_cb(CPUState *env, target_ulong oldval, target_ulong newval) {
    
    // find the process that we want.
    panda::win::ptr_t eproc = panda::win::get_current_proc(env);
    OsiProcess proc;
    panda::win::fill_OsiProcess(env, eproc, proc);
    
    g_in_process = false;
    //panda_disas
    if (g_target_proc_pid > 0) {
        g_in_process = proc.pid == g_target_proc_pid;
        
    } else {
        if (g_target_proc_name != NULL) {
            if (strcmp(proc.imageName.c_str(), g_target_proc_name) == 0) {
                g_in_process = true;
                g_target_proc_pid = proc.pid;
                
                fprintf(g_debug_log, "found target PROCESS\n");
                dump_OsiProcess(g_debug_log, proc);
            }
            
            
        }
        
    }
    
    return 0;
}

bool init_plugin(void *self) {
    
    g_debug_log = NULL;
    g_pc_prev = 0;
    //g_KiServiceTable = 0;
    
#if defined(TARGET_I386)
    
    g_debug_log = fopen("api_logger.log", "w");
    
    if (g_debug_log) {
        fprintf(g_debug_log, "Initializing plugin '%s'\n", N__PLUGIN_NAME__);
        
        panda_arg_list *args = panda_get_args(N__PLUGIN_NAME__);
        uint32_t target_pid = panda_parse_uint32(args, "pid", 0);
        const char * target_name = panda_parse_string(args, "name", NULL);
        
        if (target_pid) {
            fprintf(g_debug_log, "target_pid=%u\n", target_pid);
            g_target_proc_pid = target_pid;
            
        } else if (target_name != NULL) {
            fprintf(g_debug_log, "pid 0 or not given, try find process name '%s'\n", target_name);
            g_target_proc_name = target_name;
            
        } else {
            fprintf(g_debug_log, "target pid error and name not given, must be 1 or greater \n");
            return false;
        }
        
    } else {
        return false;
    }
    
    panda_enable_precise_pc();
    panda_enable_memcb();

    //printf("g_panda_env=0x%p\n", g_panda_env);
    //printf("g_loop_detector_engine=0x%p\n", g_loop_detector_engine);

    panda_cb pcb;

    pcb.asid_changed = on_after_asid_changed_cb;
    panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);
    pcb.insn_translate = on_insn_translate_cb;
    panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);
    pcb.insn_exec = on_insn_exec_cb;
    panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);
    
    return true;
    
#endif
    
    return false;
    
}

void uninit_plugin(void *self) {
    
    // dump all information in loop here
    // maybe later I'll add the interface function
    
    if (g_debug_log) {
        fprintf(g_debug_log, "uninit_plugin\n");
    }
    
    if (g_debug_log) {
        fclose(g_debug_log);
    }
}
