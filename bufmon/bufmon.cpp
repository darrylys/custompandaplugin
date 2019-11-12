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

//extern "C" {

// Found several instances of config.h in panda1
//#include "config.h"
//#include "qemu-common.h"
//#include "monitor.h"
//#include "cpu.h"
//#include "disas.h"

// original
//#include "panda/plugin.h"
//#include "panda/rr/rr_log.h"
//#include "callstack_instr/prog_point.h"
//#include "panda/plog.h"
//#include "callstack_instr/callstack_instr_ext.h"
//}

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>
#include <list>
#include <fstream>
#include <algorithm>

// move here:
#include "panda/plugin.h"
#include "panda/rr/rr_log.h"
#include "callstack_instr/prog_point.h"
#include "panda/plog.h"
#include "callstack_instr/callstack_instr_ext.h"

#include "win7util.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

}

struct bufdesc { target_ulong buf; target_ulong size; target_ulong cr3; };

std::list<bufdesc> bufs;
FILE *mem_report;

char get_printable(uint8_t data) {
	if (data >= 0x20 && data <= 0x7e) {
		return (char) data;
	} else {
		return '.';
	}
}

int mem_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf, bool is_write) {
    prog_point p = {};
    get_prog_point(env, &p);
	bool in_kernel = panda_in_kernel(env);
	target_ulong current_asid = panda_current_asid(env);
	/*if (in_kernel) {
		// in kernel, p.cr3 is always 0 -> set by get_prog_point callback.
		fprintf(mem_report, "[KERNEL], current_asid=" TARGET_FMT_lx " p.cr3=" TARGET_FMT_lx "\n",
				panda_current_asid(env), p.cr3);
	}*/
	
    std::list<bufdesc>::iterator it;
    for(it = bufs.begin(); it != bufs.end(); it++) {
        //if (p.cr3 != it->cr3) continue;
		if (p.sidFirst != it->cr3) continue;
        target_ulong buf_first, buf_last;
        buf_first = it->buf;
        buf_last = it->buf + it->size - 1;
        if ((addr <= buf_first && buf_first < addr+size) ||
            (addr <= buf_last && buf_last < addr+size)   ||
            (buf_first <= addr && addr <= buf_last)      ||
            (buf_first <= addr+size && addr+size <= buf_last)) {
			
			// in kernel mode, pid and tid might exist, but
			// when the process is suspended, and rewritten using WriteProcessMemory / the like
			// the pid is unreadable, but the asid is ok. This makes it only possible to know that the process is
			// written, but does not know who writes it. The kernel has different stack than the user mode. No
			// user code from user module will be found in kernel stack. In this respect, kernel-user mode
			// interaction is like client-server http model.
			target_ulong pid = win7::get_pid(env);
			target_ulong tid = win7::get_tid(env);
            fprintf(mem_report, "%s %" PRId64 " p.caller=" TARGET_FMT_lx " p.pc=" TARGET_FMT_lx " p.cr3="
                TARGET_FMT_lx " addr=" TARGET_FMT_lx " size=" TARGET_FMT_lx " pid=" TARGET_FMT_lu " tid=" TARGET_FMT_lu
				" in_kernel=%d pc=" TARGET_FMT_lx " current_asid=" TARGET_FMT_lx,
                is_write ? "W" : "R", rr_get_guest_instr_count(),
                p.caller, p.pc, p.sidFirst, addr, size, pid, tid, in_kernel, pc, current_asid);
            for (size_t i = 0; i < size; i++) {
                fprintf(mem_report, " %02x", *(((uint8_t *)buf)+i));
            }
			fprintf(mem_report, " |");
			for (size_t i = 0; i < size; i++) {
                fprintf(mem_report, " %c", get_printable(*(((uint8_t *)buf)+i)));
            }
            fprintf(mem_report, "\n");
        }
    }

    return 1;
}

int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf) {
    return mem_callback(env, pc, addr, size, buf, true);
}

int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf) {
    return mem_callback(env, pc, addr, size, buf, false);
}

int asid_changed(CPUState *env, target_ulong oldval, target_ulong newval) {
	fprintf(mem_report, "A " TARGET_FMT_lx " --> " TARGET_FMT_lx "\n", oldval, newval);
	return 0;
}

void hard_check_os_windows_7_x86() {
	assert(panda_os_familyno == OS_WINDOWS);
    assert(panda_os_bits == 32);
    assert(0 == strcmp(panda_os_variant, "7"));
}

bool init_plugin(void *self) {
	#ifdef TARGET_I386
	
	hard_check_os_windows_7_x86();
	
    panda_cb pcb;

    printf("Initializing plugin bufmon\n");

    // Need this to get EIP with our callbacks
    panda_enable_precise_pc();
    // Enable memory logging
    panda_enable_memcb();

    std::ifstream buffile("search_buffers.txt");
    if (!buffile) {
        printf("Couldn't open search_buffers.txt; no buffers to search for. Exiting.\n");
        return false;
    }

    bufdesc b = {};
    while (buffile >> std::hex >> b.buf) {
        buffile >> std::hex >> b.size;
        buffile >> std::hex >> b.cr3;

        printf("Adding buffer [" TARGET_FMT_lx "," TARGET_FMT_lx "), CR3=" TARGET_FMT_lx "\n",
               b.buf, b.buf+b.size, b.cr3);
        bufs.push_back(b);
    }
    buffile.close();

    mem_report = fopen("buffer_taps.txt", "w");
    if(!mem_report) {
        perror("fopen");
        return false;
    }

    if(!init_callstack_instr_api()) return false;

    //pcb.virt_mem_read = mem_read_callback;
    pcb.virt_mem_after_read = mem_read_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_READ, pcb);
    pcb.virt_mem_before_write = mem_write_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_BEFORE_WRITE, pcb);
	pcb.asid_changed = asid_changed;
	panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);

    return true;
	
	#endif
	
	return false;
}

void uninit_plugin(void *self) {

	#ifdef TARGET_I386
    fclose(mem_report);
	#endif
}
