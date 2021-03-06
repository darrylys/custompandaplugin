/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

extern "C" {

//#include "config.h"
//#include "qemu-common.h"
//#include "monitor.h"
//#include "cpu.h"
//#include "disas.h"
//
//#include "panda_plugin.h"

}

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>
#include <set>
#include <iostream>
#include <fstream>

//#include "../common/prog_point.h"
//#include "pandalog.h"
//#include "../callstack_instr/callstack_instr_ext.h"

#include "panda/plugin.h"
#include "panda/rr/rr_log.h"
#include "callstack_instr/prog_point.h"
#include "panda/plog.h"
#include "callstack_instr/callstack_instr_ext.h"


// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

}

std::set<prog_point> tap_points;

bool done = false;

void mem_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       size_t size, uint8_t *buf) {
    if(done) return;

    prog_point p = {};

    get_prog_point(env, &p);

    if (tap_points.find(p) != tap_points.end()) {
        tap_points.erase(p);
        char path[256];
        sprintf(path, TARGET_FMT_lx "." TARGET_FMT_lx "." TARGET_FMT_lx ".mem",
            p.caller, p.pc, p.sidFirst);
        FILE *f = fopen(path, "wb");
        panda_memsavep(f);
        fclose(f);
    }
    
    if (tap_points.empty()) done = true;

    return;
}

bool init_plugin(void *self) {
    panda_cb pcb;

    printf("Initializing plugin memsnap\n");
    
    std::ifstream taps("tap_points.txt");
    if (!taps) {
        printf("Couldn't open tap_points.txt; no tap points defined. Exiting.\n");
        return false;
    }

    prog_point p = {};
    while (taps >> std::hex >> p.caller) {
        taps >> std::hex >> p.pc;
        taps >> std::hex >> p.sidFirst;

        printf("Adding tap point (" TARGET_FMT_lx "," TARGET_FMT_lx "," TARGET_FMT_lx ")\n",
               p.caller, p.pc, p.sidFirst);
        tap_points.insert(p);
    }
    taps.close();

    if(!init_callstack_instr_api()) return false;

    panda_enable_precise_pc();
    panda_enable_memcb();    
    pcb.virt_mem_after_read = mem_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_READ, pcb);
    pcb.virt_mem_before_write = mem_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_BEFORE_WRITE, pcb);

    return true;
}

void uninit_plugin(void *self) {

}
