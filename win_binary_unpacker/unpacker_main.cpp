/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "panda/plugin.h"
#include "panda/common.h"
#include "netbeans.h"

#include "config.h"
#include "logger.h"

#include "winhelper.h"
#include "proc_info.h"

#include "Win32ProcDumper.h"
#include "Win32ProcParser.h"

#include "types.h"

// EXPORTED FUNCTIONS for PANDA

extern "C" {
    bool init_plugin(void *);
    void uninit_plugin(void *);

    //PANDA_CB_VIRT_MEM_BEFORE_READ
    int on_virt_mem_before_read(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size);

    //PANDA_CB_VIRT_MEM_BEFORE_WRITE
    int on_virt_mem_before_write(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

    //PANDA_CB_ASID_CHANGED
    int on_asid_changed(CPUState *env, target_ulong oldval, target_ulong newval);

    //PANDA_CB_INSN_TRANSLATE
    bool on_before_insn_translate(CPUState *env, target_ulong pc);

    //PANDA_CB_INSN_EXEC
    int on_before_insn_exec(CPUState *env, target_ulong pc);

}

// GLOBAL VARIABLES

unpacker::config::Config& g_config = unpacker::config::Config::getInstance();
bool g_in_process = false;

panda::win::dumper::Win32ProcDumper g_win32_proc_dumper;
unpacker::winpe32::Win32ProcParser g_win32_proc_parser;

// might change to map, maps PID to process
unpacker::ProcessInfo g_proc_info(g_win32_proc_dumper, g_win32_proc_parser);


// FUNCTION BODIES

/**
 *
 * @param env
 * @param pc
 * @param addr
 * @param size
 * @return
 */
int on_virt_mem_before_read(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size) {
    // does nothing
    return 0;
}

// currently, just record what is written BY THE Target Process to Target Process address space (CR3)
// For now, we wanted more,
// The problem is because the CPU might send some pages to disk at any time without notification
// So, when the panda tool wanted to access them, it is inaccesible.
// To fix this, the tool records all writes done to the CR3 of Target Process, ignoring the source
// how to identify this? The tool only know the target process name.
// one solution is to monitor the execution first and find the target process CR3 first
// then run another one with the target CR3
int on_virt_mem_before_write(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf) {

#if defined(TARGET_I386)

    // Monitor ALL Writes to CR3 of the target process, regardless of source

    //if (g_in_process) {
        CPUArchState * arch = reinterpret_cast<CPUArchState*>(env->env_ptr);

        // WriteProcessMemory writes to different cr3, while still running in the same process
        // For now, only monitor writes to THIS process only
        if (arch->cr[3] == g_config.get_target_cr3()) {
            // mark all writes
            g_proc_info.set_mem_written(pc, addr, (unpacker::types::size_t)size, buf);

        } else {
            // might write to different process here, quite possible injection
            // possible to translate cr3 to PID. List all processes and its cr3.
            // the rest just simple maps and finds
//            MYINFO("Possible process injection detected (target cr3 = 0x%016lx",
//                    (uint64_t)(arch->cr[3]));

        }
    //}

#endif

    return 0;
}

// This function seems only executed in kernel mode.
// because this is when CPU changes the CR3. Should've noticed that!
int on_asid_changed(CPUState *env, target_ulong oldval, target_ulong newval) {

#if defined(TARGET_I386)

    //CPUArchState * arch = reinterpret_cast<CPUArchState*>(env->env_ptr);

    // find the process that we want.
    panda::win::ptr_t eproc = panda::win::get_current_proc(env);
    OsiProcess proc;
    panda::win::fill_OsiProcess(env, eproc, proc);

    g_in_process = false;
    //panda_disas
    if (g_config.get_target_pid() > 0) {
        g_in_process = proc.pid == g_config.get_target_pid();

    } else {
        if (g_config.get_target_proc_name() != NULL) {
            if (strcmp(proc.imageName.c_str(), g_config.get_target_proc_name()) == 0) {
                g_in_process = true;
                g_config.set_target_pid(proc.pid);

                MYINFO("found target PROCESS {pid=%d, parentid=%d}", proc.pid, proc.ppid);
                dump_OsiProcess(proc);
            }


        }

    }

    if (g_in_process) {

        // TODO: check if in kernel. if so, ignore


        g_proc_info.set_pid(proc.pid);
        g_proc_info.set_ppid(proc.ppid);
        g_proc_info.set_proc_name(proc.imageName.c_str());
        g_proc_info.set_base_addr(panda::win::get_image_base_addr(
                    env, panda::win::get_current_proc(env) ) );
//        g_proc_info.parse_module(panda::win::get_image_base_addr(
//                    env, panda::win::get_current_proc(env)), (void*)env);

//        if (g_proc_info.get_module().get_base_addr() == 0) {
//            g_proc_info.get_module().set_base_addr(panda::win::get_image_base_addr(
//                    env, panda::win::get_current_proc(env)));
//            MYINFO("target process base address is: 0x%016x",
//                    g_proc_info.get_module().get_base_addr());
//        }

        if (g_config.get_target_cr3() == 0) {
            g_config.set_target_cr3(proc.asid);
        }

        // suspect!!
        // must know when to take the correct cr3!
        // g_target_cr3 = arch->cr[3];
    }

#endif

    return 0;

}

bool on_before_insn_translate(CPUState *env, target_ulong pc) {

#if defined(TARGET_I386)

    if (g_in_process) {
        CPUArchState * arch = reinterpret_cast<CPUArchState*>(env->env_ptr);
        target_ulong current_cr3 = arch->cr[3];

        if (g_config.get_target_cr3() == current_cr3) {

            // here, the image base address is just plain weird.
            // however, the base image address is correct in asid_changed function
            g_proc_info.parse_module((void*)env);

            g_win32_proc_dumper.set_env(env);
            g_proc_info.check_eip(pc, (void*)env);
        }

        return false;
    }

#endif

    // no need to instrument them, just the address first time execution
    // in that case, simply check before the instruction is translated
    return false;
}

int on_before_insn_exec(CPUState *env, target_ulong pc) {
    return 0;
}

bool init_plugin(void * self) {

    bool ret = false;

#if defined(TARGET_I386)

    ret = true;

    if (!g_config.init()) {
        ret = false;
        printf("%s\n", "Config initialization error");
    }

    MYINFO(">> init_plugin(%s)", g_config.get_plugin_name());

    if (ret) {
        panda_arg_list *args = panda_get_args(g_config.get_plugin_name());
        uint32_t target_pid = panda_parse_uint32(args, "pid", 0);
        const char * target_name = panda_parse_string(args, "name", NULL);
        uint64_t target_cr3 = panda_parse_uint64(args, "cr3", 0);
        g_config.set_target_cr3(target_cr3);

        if (target_pid) {
            MYINFO("target_pid=%u\n", target_pid);
            g_config.set_target_pid(target_pid);

        } else if (target_name != NULL) {
            MYINFO("pid 0 or not given, try find process name '%s'", target_name);
            g_config.set_target_proc_name(target_name);

        } else {
            MYERROR("%s", "target pid error and name not given, must be 1 or greater");
            ret = false;
        }
    }

    if (ret) {

        panda_enable_precise_pc();
        panda_enable_memcb();

        panda_cb pcb;

        pcb.asid_changed = on_asid_changed;
        panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);

        pcb.virt_mem_before_read = on_virt_mem_before_read;
        panda_register_callback(self, PANDA_CB_VIRT_MEM_BEFORE_READ, pcb);

        pcb.virt_mem_before_write = on_virt_mem_before_write;
        panda_register_callback(self, PANDA_CB_VIRT_MEM_BEFORE_WRITE, pcb);

        pcb.insn_exec = on_before_insn_exec;
        panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);

        pcb.insn_translate = on_before_insn_translate;
        panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);

        ret = true;

    }

#endif

    MYINFO("<< init_plugin(): %d", ret);

    return ret;

}

void uninit_plugin(void * self) {

    MYINFO (">> uninit_plugin(%s)", g_config.get_plugin_name());

    MYINFO ("%s", "<< uninit_plugin()");

}

