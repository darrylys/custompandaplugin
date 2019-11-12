
//#define NETBEANS

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "loopdetector.h"
#include "winhelper.h"

#ifdef NETBEANS
#include "exec/cpu-all.h"
#endif

#ifdef NETBEANS
typedef uint64_t target_ulong;
#endif

#define N__PLUGIN_NAME__ "unpldet"

namespace loopdetector {
    
    class PandaEnvAccessor : public EnvironmentAccessor {
    public:
        
        /**
         * Creates PandaEnvAccessor
         * @param debug_log the debug log file. This is later used by LoopDetector engine. default: NULL
         */
        PandaEnvAccessor(FILE * debug_log = NULL) 
        : m_debug_log(debug_log), m_env(NULL) {
            
        }
        
        virtual ~PandaEnvAccessor() {
            
        }
        
        /**
         * Call this before calling any LoopDetector functions to set the environment correctly
         * Don't forget to NULL it after usage
         * @param env, Panda CPUState pointer
         */
        void set_env(CPUState *env) {
            this->m_env = env;
        }
        
    private:
        FILE * m_debug_log;
        CPUState * m_env;
        
        virtual int impl_read_mem(types::ADDRINT src, types::BYTE *out, int size) {
            if (this->m_env == NULL || -1 == panda_virtual_memory_read(m_env, src, out, size)) {
                return 0;
            }
            return size;
        }
        
        virtual void impl_debug_print(const char * str) {
            if (this->m_debug_log) {
                fprintf(this->m_debug_log, "%s\n", str);
            }
        }
        
    };
    
}

extern "C" {
    bool init_plugin(void *);
    void uninit_plugin(void *);
    
    int on_after_asid_changed_cb(CPUState *env, target_ulong oldval, target_ulong newval);
    int on_before_virt_mem_write(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
}

FILE * g_debug_log;
loopdetector::PandaEnvAccessor * g_panda_env;
loopdetector::LoopDetector * g_loop_detector_engine;
bool g_in_process;
uint32_t g_target_proc_pid;
const char * g_target_proc_name;

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

int on_before_virt_mem_write(CPUState *env, target_ulong pc, target_ulong addr, 
        target_ulong size, void *buf) {
    
    if (g_in_process) {
    
        /* analyze the loop of the process that we want
         * and just the user code only
         * it seems that user code only is more accurate.
         * 
         * There are only few ways to write stuff to memory
         * 1. manual assembly / loop in user code
         * 2. using API
         * 
         * In order to use API for
         * 1. Write to disk, and map it to program space
         * 2. Use memcpy / WriteProcessMemory / NtWriteVirtualMemory
         *    
         * When using the ready API, the complete buffer to write must exist
         * in memory. To do this, one have to use manual approach
         * 
         * One method left is using EncryptDecrypt func in WinAPI. This can 
         * be handled with different panda plugin instead.
         */
        //if (pc < (uint32_t)0x70000000) 
        {
            //printf("pc=0x%08x\n", (uint32_t)pc);
            g_panda_env->set_env(env);
            g_loop_detector_engine->before_virt_mem_write(
                (loopdetector::types::ADDRINT)pc, 
                (loopdetector::types::ADDRINT)addr, 
                buf, 
                (loopdetector::types::SIZE_T)size);
            
            g_loop_detector_engine->before_ins_exec(
                (loopdetector::types::ADDRINT)pc, "");
            
            g_panda_env->set_env(NULL);
        }
    }
    
    return 0;
}


bool init_plugin(void *self) {
    
    g_debug_log = NULL;
    g_panda_env = NULL;
    g_loop_detector_engine = NULL;
    g_in_process = false;
    
#if defined(TARGET_I386)
    
    g_debug_log = fopen("loop_detector.debug.log", "w");
    
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
    }
    
    panda_enable_precise_pc();
    panda_enable_memcb();

    g_panda_env = new loopdetector::PandaEnvAccessor(g_debug_log);
    g_loop_detector_engine = new loopdetector::LoopDetector(g_panda_env);

    //printf("g_panda_env=0x%p\n", g_panda_env);
    //printf("g_loop_detector_engine=0x%p\n", g_loop_detector_engine);

    panda_cb pcb;

    pcb.asid_changed = on_after_asid_changed_cb;
    panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);

    pcb.virt_mem_before_write = on_before_virt_mem_write;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_BEFORE_WRITE, pcb);
    
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
    
    delete g_loop_detector_engine;
    delete g_panda_env;
    
    if (g_debug_log) {
        fclose(g_debug_log);
    }
}
