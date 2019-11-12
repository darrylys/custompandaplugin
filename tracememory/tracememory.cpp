/* PANDABEGINCOMMENT
 * 
 * Authors:
 * 	Suhandi	suhandi@student.sgu.ac.id
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */

#define __STDC_FORMAT_MACROS

extern "C" {
#include "panda/plog.h"
}

#include <cstdio>
#include <cstdlib>

#include <iostream>
#include <fstream>
#include <algorithm>
#include <map>
#include <set>
#include <vector>
#include <list>

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"
#include "panda/rr/rr_log.h"
#include "callstack_instr/callstack_instr.h"
#include "callstack_instr/callstack_instr_int_fns.h"

#include <capstone/capstone.h>

#if defined(TARGET_I386)
    #include <capstone/x86.h>
#elif defined(TARGET_ARM)
    #include <capstone/arm.h>
#elif defined(TARGET_PPC)
    #include <capstone/ppc.h>
#endif

bool active = false;
long long begin_at = 0;
long long exit_at = -1;
FILE * plugin_log; // not yet opened, plugin_log is a null pointer!

typedef struct buffdesc { 
    target_ulong buf; 
    target_ulong size; 
    target_ulong cr3; 
}bufs;

//struct bufferdesc { 
//    target_ulong buf; 
//    target_ulong size; 
//    target_ulong cr3; 
//};

// ~Darryl, change the std::list with normal array
// iteration uses normal for(int i=0;i<len;++i).
// e.g. bufferdesc b1[2048];
//      int b1_len = 0; // length of b1 array that is used

//std::list<bufferdesc> b1;

int mem_write_callback(CPUState *cpu, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
int mem_read_callback(CPUState *cpu, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
int after_block_callback(CPUState *cpu, TranslationBlock *tb, TranslationBlock *next_tb);
int before_block_callback(CPUState *cpu, TranslationBlock *tb);
int guest_hypercall_callback(CPUState *cpu);
bool translate_callback(CPUState *cpu, target_ulong pc);
int exec_callback(CPUState *cpu, target_ulong pc);

extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);
//int monitor_callback(Monitor *mon, const char *cmd);
}

//Getting from callstack_instr.cpp
static inline bool in_kernelspace(CPUArchState* env) {
    #if defined(TARGET_I386)
        return ((env->hflags & HF_CPL_MASK) == 0);
    #elif defined(TARGET_ARM)
        return ((env->uncached_cpsr & CPSR_M) == ARM_CPU_MODE_SVC);
    #else
        return false;
    #endif
}

//Getting from callstack_instr.cpp
// segfault shouldn't be thrown here
void get_prog_point(CPUState* cpu, prog_point *p) {
    CPUArchState* env = (CPUArchState*)cpu->env_ptr;
    if (!p) return;

    // p is zeroed

    // Get address space identifier
    target_ulong asid = panda_current_asid(ENV_GET_CPU(env));
    // Lump all kernel-mode CR3s together

    if(!in_kernelspace(env))
        p->cr3 = asid;

    // Try to get the caller
    int n_callers = 0;
    //n_callers = get_callers(&p->caller, 1, cpu);

    if (n_callers == 0) {
        #ifdef TARGET_I386
                // fall back to EBP on x86
                int word_size = (env->hflags & HF_LMA_MASK) ? 8 : 4;
                panda_virtual_memory_rw(cpu, env->regs[R_EBP]+word_size, (uint8_t *)&p->caller, word_size, 0);
        #endif
        #ifdef TARGET_ARM
                p->caller = env->regs[14]; // LR
        #endif
    }

    p->pc = cpu->panda_guest_pc;
}

// segfault shouldn't be thrown here
int mem_callback(CPUState *cpu, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf, bool is_write) {
                       
    prog_point p = {}; // p is zeroed here
    get_prog_point(cpu, &p);

//    long it; // unused variable, compile error
    buffdesc bufs{}; // bufs is zeroed out.
        
    // ~Darryl, what is this for?
    //for(it = bufs.begin(); it != bufs.end(); it++) {
        //if (p.cr3 != bufs.cr3) continue;

        target_ulong buf_first, buf_last; // target_ulong = uint32_t = unsigned int        
        
        buf_first = bufs.buf; // buf_first = 0, bufs.buf = 0
        
        buf_last = bufs.buf + bufs.size - 1; // buf_last = 0xFFFFFFFF because of underflow!
        if (
        (addr <= buf_first && buf_first < addr+size) || // false
        (addr <= buf_last && buf_last < addr+size)   || // false
        (buf_first <= addr && addr <= buf_last)      || // true because all addr MUST BE within 0 to 0xFFFFFFFF.
        (buf_first <= addr+size && addr+size <= buf_last)
        ) {

        fprintf(plugin_log, "%s %" PRId64 " " TARGET_FMT_lx " " TARGET_FMT_lx " " 
            TARGET_FMT_lx " " TARGET_FMT_lx " " TARGET_FMT_lx,
            is_write ? "WRITE" : "READ", rr_get_guest_instr_count(),
            p.caller, p.pc, p.cr3, addr, size);
            for (size_t i = 0; i < size; i++) {
               fprintf(plugin_log, " %02x", *(((uint8_t *)buf)+i));
            }
            fprintf(plugin_log, "\n");
        }
    //}
    return 1;
}

int guest_hypercall_callback(CPUState* cpu) {
    #ifdef TARGET_I386
        CPUArchState* env = (CPUArchState*)cpu->env_ptr;
        if(env->regs[R_EAX] == 0xdeadbeef) printf("Hypercall called!\n");
    #endif
    return 1;
}

// write this program point to this file
static void rr_spit_prog_point_fp(FILE *fp, RR_prog_point pp) {
    fprintf(fp, "{guest_instr_count=%llu",
        (unsigned long long)pp.guest_instr_count);
}

int before_block_callback(CPUState* cpu, TranslationBlock *tb) {
    #ifdef TARGET_I386
        CPUArchState* env = (CPUArchState*)cpu->env_ptr;
    #endif
        RR_prog_point pp = rr_prog_point();
        if (pp.guest_instr_count >= begin_at) active = true;
        if (exit_at != -1 && pp.guest_instr_count >= exit_at) {
            rr_end_replay_requested = 1;
            active = false;
        }
        if (!active) return 1;
        rr_spit_prog_point_fp(plugin_log, pp);
        fprintf(plugin_log, "Next TB: " TARGET_FMT_lx 
        #ifdef TARGET_I386
                ", CR3=" TARGET_FMT_lx
        #endif
                 "%s\n", tb->pc,
        #ifdef TARGET_I386
                env->cr[3],
        #endif
            "");
        return 0;
   
}

int after_block_callback(CPUState* cpu, TranslationBlock *tb, TranslationBlock *next_tb) {
    #ifdef TARGET_I386
        CPUArchState* env = (CPUArchState*)cpu->env_ptr;
    #endif
    if (!active) return 1;
    fprintf(plugin_log, "After TB " TARGET_FMT_lx 
    #ifdef TARGET_I386
            ", CR3=" TARGET_FMT_lx
    #endif
            " next TB: " TARGET_FMT_lx "\n", tb->pc,
    #ifdef TARGET_I386
            env->cr[3],
    #endif
            next_tb ? next_tb->pc : 0);
    return 1;
}

// We're going to log all user instructions
bool translate_callback(CPUState *cpu, target_ulong pc) {
    // We have access to env here, so we could choose to
    // read the bytes and do something fancy with the insn
    return pc < 0x80000000;
}

int exec_callback(CPUState *cpu, target_ulong pc) {
    //CPUArchState* env = (CPUArchState*)cpu->env_ptr;
    if (!active) return 1;
    fprintf(plugin_log, "User insn 0x" TARGET_FMT_lx " executed:", pc);
    // An x86 instruction must always fit in 15 bytes; this does not
    // make much sense for other architectures, but is just for
    // testing and debugging
    unsigned char buf[15];
    panda_virtual_memory_rw(cpu, pc, buf, 15, 0);
    
    int i;
    for (i = 0; i < 15; i++) {
        fprintf(plugin_log, " %02x", buf[i]);
    }
    fprintf(plugin_log, "\n");
    return 1;
}

int mem_write_callback(CPUState *cpu, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    return mem_callback(cpu, pc, addr, size, buf, true);
}
int mem_read_callback(CPUState *cpu, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    return mem_callback(cpu, pc, addr, size, buf, false);
}

bool init_plugin(void *self) {
    panda_cb pcb;
    printf("Initializing plugin trace memory\n");

    // ~Darryl, open the file to use for plugin log!
    // the plugin_log is NULL and throws segmentation fault when used in fprintf!
    plugin_log = fopen("tracememory.log", "w");

    // Need this to get EIP with our callbacks
    panda_enable_precise_pc();
    // Enable memory logging
    panda_enable_memcb();

    std::ifstream buffile("search_buffers.txt");
    if (!buffile) {
        printf("Couldn't open search_buffers.txt; no buffers to search for. Exiting.\n");
        return false;
    }
    
    // ~Darryl
    // this is local variable in a function
    // this reading is meaningless because the object buffdesc b is removed
    // at the end of this function.
    // put the inputs in an array!
    buffdesc b = {};
    while (buffile >> std::hex >> b.buf) {
        buffile >> std::hex >> b.size;
        buffile >> std::hex >> b.cr3;
        printf("Adding buffer [" TARGET_FMT_lx "," TARGET_FMT_lx "), CR3=" TARGET_FMT_lx "\n",
               b.buf, b.buf+b.size, b.cr3);
               
        // using array example:
        // int i = b1_len;
        // b1[i] = b; // using copy constructor
        // i++;
    }
    buffile.close();

    // Old Order of Callbacks
    
    pcb.virt_mem_after_read = mem_read_callback;
    
    // ~Darryl
    // Original:  panda_register_callback(self, PANDA_CB_VIRT_MEM_BEFORE_READ, pcb);
    // Should be PANDA_CB_VIRT_MEM_AFTER_READ, matches with pcb.virt_mem_after_read above.
    // This caused the segmentation fault!
    panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_READ, pcb);
    
    // the following are OK
    pcb.virt_mem_after_write = mem_write_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_WRITE, pcb);
    pcb.guest_hypercall = guest_hypercall_callback;
    panda_register_callback(self, PANDA_CB_GUEST_HYPERCALL, pcb);
    pcb.insn_translate = translate_callback;
    panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);
    pcb.insn_exec = exec_callback;
    panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);
    
    return true;
}

void uninit_plugin(void *self) {
    //panda_free_args(args);
    
    if (plugin_log) {
        fflush(plugin_log);
        fclose(plugin_log);
    }
}
