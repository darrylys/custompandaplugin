/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include <stdio.h>
#include <string.h>

#include "panda/plugin.h"
#include "panda/common.h"

#include "netbeans.h"
#include "winxphdr.h"

#define PLUGIN_NAME "mem_logger"

extern "C" {
    bool init_plugin(void *);
    void uninit_plugin(void *);
    int on_virt_mem_before_write(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
    int on_virt_mem_before_read(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size);
    
    int on_phys_mem_before_write(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
//    int on_phys_mem_before_read(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size);
    
}

// not supporting 64-bits!
typedef uint32_t ptr_t;

ptr_t get_kpcr(CPUState *env) {
#if defined(TARGET_I386)
        CPUArchState *arch = reinterpret_cast<CPUArchState*>(env->env_ptr);
    return arch->segs[R_FS].base;
#endif
        return 0;
}

ptr_t get_current_proc(CPUState *env, ptr_t kpcr = 0) {

    ptr_t thread, proc, fs_base;

    if (kpcr == 0) {
        kpcr = get_kpcr(env);
    }
    fs_base = kpcr; 

    // Read KPCR->CurrentThread->Process
    panda_virtual_memory_rw(env, fs_base+KPCR_CURTHREAD_OFF, (uint8_t *)&thread, sizeof(ptr_t), false);
    panda_virtual_memory_rw(env, thread+ETHREAD_EPROC_OFF, (uint8_t *)&proc, sizeof(ptr_t), false);

    return proc;
}

ptr_t get_pid(CPUState *env, ptr_t eproc) {
    ptr_t pid;
    panda_virtual_memory_rw(env, eproc+EPROC_PID_OFF, (uint8_t *)&pid, sizeof(ptr_t), false);
    return pid;
}

ptr_t get_ppid(CPUState *env, ptr_t eproc) {
    ptr_t ppid;
    panda_virtual_memory_rw(env, eproc+EPROC_PPID_OFF, (uint8_t *)&ppid, sizeof(ptr_t), false);
    return ppid;
}

uint32_t get_current_pid(CPUState *env) {
    ptr_t eproc = get_current_proc(env);
    return get_pid(env, eproc);
}

FILE * g_logger;

bool init_plugin(void * self) {
    printf(">> init_plugin %s\n", PLUGIN_NAME);
    
    char buf[32];
    sprintf(buf, "%s.log", PLUGIN_NAME);
    g_logger = fopen(buf, "w");
    
    bool ret = false;
    
    if (g_logger) {
    
        panda_enable_precise_pc();
        panda_enable_memcb();

        panda_cb pcb;

        pcb.virt_mem_before_write = on_virt_mem_before_write;
        panda_register_callback(self, PANDA_CB_VIRT_MEM_BEFORE_WRITE, pcb);

        pcb.virt_mem_before_read = on_virt_mem_before_read;
        panda_register_callback(self, PANDA_CB_VIRT_MEM_BEFORE_READ, pcb);
        
        pcb.phys_mem_before_write = on_phys_mem_before_write;
        panda_register_callback(self, PANDA_CB_PHYS_MEM_BEFORE_WRITE, pcb);
        
        ret = true;
        
    } else {
        printf("unable to open file %s\n", buf);
        
    }
    
    printf("<< init_plugin(): %d\n", ret);
    
    
    return ret;
}

void uninit_plugin(void * self) {
    printf(">> uninit_plugin()");
    
    if (g_logger) {
        fclose(g_logger);
    }
    
    printf("<< uninit_plugin()");
}

int on_virt_mem_before_read(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size) {
    
#if defined (TARGET_I386)
    
        
    uint64_t data = 0;
    if (panda_virtual_memory_read(env, addr, (uint8_t*)(&data), size) != -1) {
        if (data == 0x5a || 
                data == 0x5a5a || 
                data == 0x5a5a5a || 
                data == (uint32_t)0x5a5a5a5a || 
                data == (uint64_t)0x5a5a5a5a5a5a5a5a) {
            
            CPUArchState * arch = reinterpret_cast<CPUArchState*>(env->env_ptr);
            uint32_t pid = get_current_pid(env);
            
            fprintf(g_logger, "virt_mem_before_read\tpid=%u\t%016lx\t%016lx\t%016lx\t%d\t%lx\n", 
                    pid, (uint64_t)(arch->cr[3]), (uint64_t)pc,(uint64_t)addr, (int)size, data);
            
        }
    }
        
    
#endif
    
    return 0;
    
}

int on_virt_mem_before_write(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf) {
    
#if defined(TARGET_I386)
    
    uint64_t data = 0;
    memcpy(&data, buf, (int)size);

    if (data == 0x5a || 
                data == 0x5a5a || 
                data == 0x5a5a5a || 
                data == (uint32_t)0x5a5a5a5a || 
                data == (uint64_t)0x5a5a5a5a5a5a5a5a) {

        CPUArchState * arch = reinterpret_cast<CPUArchState*>(env->env_ptr);
        uint32_t pid = get_current_pid(env);
        
        fprintf(g_logger, "virt_mem_before_write\tpid=%u\t%016lx\t%016lx\t%016lx\t%d\t%lx\n", 
                pid, (uint64_t)(arch->cr[3]), (uint64_t)pc,(uint64_t)addr, (int)size, data);
    }
    
#endif
    return 0;
}

int on_phys_mem_before_write(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf) {
    
#if defined(TARGET_I386)
    
//    if (size == 1) { 
    
    uint64_t data = 0;
    memcpy(&data, buf, (int)size);

    if (data == 0x5a || 
            data == 0x5a5a || 
            data == 0x5a5a5a || 
            data == (uint32_t)0x5a5a5a5a || 
            data == (uint64_t)0x5a5a5a5a5a5a5a5a) {

        CPUArchState * arch = reinterpret_cast<CPUArchState*>(env->env_ptr);
        uint32_t pid = get_current_pid(env);
        
        fprintf(g_logger, "phys_mem_before_write\tpid=%u\t%016lx\t%016lx\t%016lx\t%d\t%lx\n",
                pid, (uint64_t)(arch->cr[3]), (uint64_t)pc,(uint64_t)addr, (int)size, data);
        
    }
        
//    }
    
#endif
    
    return 0;
}


