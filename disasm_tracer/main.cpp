/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "panda/plugin.h"
#include "panda/common.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <map>
using std::map;

#include "netbeans_stuff.h"

#include "winhelper.h"
#include "utility.h"
#include "pandawinpeheader.h"

#define PLUGIN_NAME "disasm_tracer"

extern "C" {
    bool init_plugin(void *);
    void uninit_plugin(void *);
    
    int on_after_asid_changed_cb(CPUState *env, target_ulong oldval, target_ulong newval);
    int on_before_block_exec(CPUState* cpu, TranslationBlock *tb);
}

map<uint32_t, FILE*> g_files;
map<uint32_t, target_ulong> g_pc_prev_map;

FILE * g_output_log;
bool g_in_process;
uint32_t g_target_proc_pid;
uint32_t g_current_proc_pid;
const char * g_target_proc_name;
utility::Disassembler * g_disasm;

void insert_file(uint32_t pid) {
    char buf[64];
    memset(buf, 0, sizeof(buf));
    sprintf(buf, "disasm_app.%u.log", pid);
    FILE * fl = fopen(buf, "w");
    if (fl) {
        g_files[pid] = fl;
    } else {
        fprintf(g_output_log, "Cannot open file '%s'\n", buf);
    }
}

int on_after_asid_changed_cb(CPUState *env, target_ulong oldval, target_ulong newval) {
    
    g_in_process = false;
    g_current_proc_pid = 0;
    
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
    
    // find the process that we want.
    panda::win::ptr_t eproc = panda::win::get_current_proc(env);
    OsiProcess proc;
    panda::win::fill_OsiProcess(env, eproc, proc);
    
    if (g_target_proc_pid == 0) {
        if (g_target_proc_name != NULL) {
            if (strncasecmp(proc.imageName.c_str(), g_target_proc_name, 15) == 0) {
                g_in_process = true;
                g_current_proc_pid = proc.pid;
                            
                if (g_files.count(proc.pid) == 0) {
                    fprintf(g_output_log, "found target PROCESS\n");
                    dump_OsiProcess(g_output_log, proc);
                    insert_file(proc.pid);
                }
                
            }// else {
                //fprintf(g_output_log, "search img: '%s'\n", proc.imageName.c_str());
            //}
        }
    } else {
        g_in_process = proc.pid == g_target_proc_pid;
        if (g_in_process) {
            g_current_proc_pid = proc.pid;
            if (g_files.count(proc.pid) == 0) {
                insert_file(proc.pid);
            }
        }
    }
    
#endif
    
    return 0;
}

int tb_disasm(CPUState *cpu, target_ulong pc, int size) {
    //::panda_disas(g_output_log, (void*)(tb->pc), tb->size);
    
    if (g_files.count(g_current_proc_pid) > 0) {
        
        FILE * file = g_files[g_current_proc_pid];
        
        uint8_t *buf = (uint8_t*)malloc(size * sizeof(uint8_t));
        int read = ::panda_virtual_memory_read(cpu, pc, buf, size);
        if (read == -1) {
            fprintf(file, "pc=%016lx, size=%d, CANNOT READ TB MEMORY!\n", 
                (uint64_t)pc, size);
            
        } else {
            bool res = g_disasm->disasm(file, buf, size, (uint64_t)pc);
            if (!res) {
                fprintf(file, "pc=%016lx, size=%d, DISASSEMBLY FAILED!\n", 
                    (uint64_t)pc, size);
                
            }
        }
        
        free(buf);
        
    }
    return 0;
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
    if (g_files.count(g_current_proc_pid) > 0) {
        
        FILE * file = g_files[g_current_proc_pid];

        panda::win::ptr_t img_base = panda::win::find_image_base_addr(env, pc);
        if (img_base) {
            winpe::WinPEPanda panda_win(env, img_base, file);
            
            string api_name = panda_win.get_api_name_from_addr(pc);
            
            fprintf(file, 
            	"img_base 0x%016lx | 0x%016lx --> 0x%016lx | %s\n", 
            	(uint64_t)img_base, 
            	(uint64_t)prev, 
            	(uint64_t)pc, 
            	api_name.c_str());
        }
    }
#endif
}

void dumpReturnAPI(CPUState *env, target_ulong pc, target_ulong prev) {
#ifdef TARGET_I386
    if (g_files.count(g_current_proc_pid) > 0) {
        
        FILE * file = g_files[g_current_proc_pid];
        
        CPUArchState * arch = reinterpret_cast<CPUArchState*>(env->env_ptr);
        target_ulong eax = arch->regs[R_EAX];
        
        // return value should be in eax
        fprintf(file, "0x%016lx --> 0x%016lx | (signed=%ld)(unsigned=%lu)(0x%016lx)\n", 
            (uint64_t)prev, 
	        (uint64_t)pc, (int64_t) eax, (uint64_t) eax, (uint64_t) eax);
	}
#endif
}

int on_before_block_exec(CPUState* env, TranslationBlock *tb) {
        
    if (g_in_process) {
        
#if defined(TARGET_I386)
        target_ulong pc = tb->pc;    
            
        if (tb->pc < 0x70000000) {
            tb_disasm(env, tb->pc, tb->size);
        }
        
        target_ulong g_pc_prev = 0;
        if (g_pc_prev_map.count(g_current_proc_pid) > 0) {
            g_pc_prev = g_pc_prev_map[g_current_proc_pid];
        }
        
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
		
		g_pc_prev_map[g_current_proc_pid] = pc;
		
#endif
        
    }
    
    return 0;
}

bool init_plugin(void *self) {
    
    g_in_process = false;
    g_output_log = ::fopen("disasm_app.log", "w");
    g_target_proc_pid = 0;
    g_target_proc_name = NULL;  
        
    if (g_output_log) {
        g_disasm = new utility::Disassembler();
        if(g_disasm->init()) {
            
            fprintf(g_output_log, "Initializing plugin\n");
            panda_arg_list *args = panda_get_args(PLUGIN_NAME);
            uint32_t target_pid = panda_parse_uint32(args, "pid", 0);
            const char * target_name = panda_parse_string(args, "name", NULL);
            
            if (target_pid > 0 || target_name != NULL) {
                if (target_pid) {
                    fprintf(g_output_log, "target_pid=%u\n", target_pid);
                    g_target_proc_pid = target_pid;

                } else if (target_name != NULL) {
                    fprintf(g_output_log, "pid 0 or not given, try find process name '%s'\n", target_name);
                    g_target_proc_name = target_name;

                }
                
                panda_enable_precise_pc();
                panda_enable_memcb();
                
                panda_cb pcb;
                pcb.asid_changed = on_after_asid_changed_cb;
                panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);
                pcb.before_block_exec = on_before_block_exec;
                panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
                
                return true;
            } else {
                fprintf(g_output_log, "target pid error and name not given, must be 1 or greater \n");
            }
        } else {
            printf("disasm failed to initialize\n");
        }
    } else {
        printf("Plugin failed to load, cannot open file disasm_app.log\n");
    }
    
    return false;
}

void uninit_plugin(void *) {
    delete g_disasm;
    
    for (map<uint32_t, FILE*>::iterator it = g_files.begin(); 
        it != g_files.end(); ++it) {
        
        fclose(it->second);
        
    }
    
    if (g_output_log != NULL) {
        fclose(g_output_log);
    }
}

