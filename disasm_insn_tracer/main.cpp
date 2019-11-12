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

#include "__netbeans.h"

#include "winhelper.h"
#include "utility.h"

#define PLUGIN_NAME "disasm_insn_tracer"

extern "C" {
    bool init_plugin(void *);
    void uninit_plugin(void *);

    //PANDA_CB_INSN_TRANSLATE
    bool on_before_insn_translate(CPUState *env, target_ulong pc);

    //PANDA_CB_INSN_EXEC
    int on_before_insn_exec(CPUState *env, target_ulong pc);

    int on_after_asid_changed_cb(CPUState *env, target_ulong oldval, target_ulong newval);
    int on_before_block_exec(CPUState* cpu, TranslationBlock *tb);
}

FILE * g_output_log;
bool g_in_process;
uint32_t g_target_proc_pid;
const char * g_target_proc_name;
utility::Disassembler * g_disasm;

int on_after_asid_changed_cb(CPUState *env, target_ulong oldval, target_ulong newval) {

    g_in_process = false;

#if defined(TARGET_I386) && !defined(TARGET_X86_64)

    // find the process that we want.
    panda::win::ptr_t eproc = panda::win::get_current_proc(env);
    OsiProcess proc;
    panda::win::fill_OsiProcess(env, eproc, proc);

    //panda_disas
    if (g_target_proc_pid > 0) {
        g_in_process = proc.pid == g_target_proc_pid;

    } else {
        if (g_target_proc_name != NULL) {
            if (strcmp(proc.imageName.c_str(), g_target_proc_name) == 0) {
                g_in_process = true;
                g_target_proc_pid = proc.pid;

                fprintf(g_output_log, "found target PROCESS\n");
                dump_OsiProcess(g_output_log, proc);
            }


        }

    }

#endif

    return 0;
}

int tb_disasm(CPUState *cpu, target_ulong pc, int size) {
    //::panda_disas(g_output_log, (void*)(tb->pc), tb->size);

    uint8_t *buf = (uint8_t*)malloc(size * sizeof(uint8_t));
    int read = ::panda_virtual_memory_read(cpu, pc, buf, size);
    if (read == -1) {
        fprintf(g_output_log, "pc=%016lx, size=%d, CANNOT READ TB MEMORY!\n", (uint64_t)pc, size);

    } else {
        bool res = g_disasm->disasm(g_output_log, buf, size, (uint64_t)pc);
        if (!res) {
            fprintf(g_output_log, "pc=%016lx, size=%d, DISASSEMBLY FAILED!\n", (uint64_t)pc, size);

        }
    }

    free(buf);
    return 0;
}

/*
int on_before_block_exec(CPUState* cpu, TranslationBlock *tb) {

    if (g_in_process) {

#if defined(TARGET_I386)
        if (tb->pc < 0x70000000) {
            tb_disasm(cpu, tb->pc, tb->size);
        }
#endif

    }

    return 0;
}
*/

bool on_before_insn_translate(CPUState *env, target_ulong pc) {

#if defined(TARGET_I386)
    return true;
#endif

    return false;
}

int on_before_insn_exec(CPUState *env, target_ulong pc) {

#if defined(TARGET_I386)

    if (g_in_process) {
        if (pc < 0x70000000) {

            CPUArchState * arch = reinterpret_cast<CPUArchState*>(env->env_ptr);

            uint8_t buf[16];

            // longest intel instruction is 15 bytes. Otherwise, it generates an exception
            int size = 15;
            int read = ::panda_virtual_memory_read(env, pc, buf, size);

            if (read == -1) {
                fprintf(g_output_log, "pc=%016lx, size=%d, CANNOT READ TB MEMORY!\n", (uint64_t)pc, size);

            } else {
                fprintf(g_output_log,
                    "REG:\n\teax: %016lx\n\tebx: %016lx\n\tecx: %016lx\n\tedx: "
                    "%016lx\n\tebp: %016lx\n\tesp: %016lx\n\tesi: %016lx\n\tedi: %016lx\n",
                    (uint64_t)arch->regs[R_EAX], (uint64_t)arch->regs[R_EBX],
                    (uint64_t)arch->regs[R_ECX], (uint64_t)arch->regs[R_EDX],
                    (uint64_t)arch->regs[R_EBP], (uint64_t)arch->regs[R_ESP],
                    (uint64_t)arch->regs[R_ESI], (uint64_t)arch->regs[R_EDI]);
                bool res = g_disasm->disasm(g_output_log, buf, size, (uint64_t)pc, 1);
                if (!res) {
                    fprintf(g_output_log, "pc=%016lx, size=%d, DISASSEMBLY FAILED!\n", (uint64_t)pc, size);
                }
                fprintf(g_output_log, "=============================\n");
            }

        } else {
            // can take note of the API called here

        }

        return 0;
    }

#endif // defined

    return 0;
}

bool init_plugin(void *self) {

    g_in_process = false;
    g_output_log = ::fopen("disasm_insn_tracer.log", "w");

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

                //pcb.before_block_exec = on_before_block_exec;
                //panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

                pcb.insn_exec = on_before_insn_exec;
                panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);

                pcb.insn_translate = on_before_insn_translate;
                panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);

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

    if (g_output_log != NULL) {
        fclose(g_output_log);
    }
}

