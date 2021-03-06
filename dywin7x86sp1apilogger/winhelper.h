/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   winhelper.h
 * Author: darryl
 *
 * Created on May 3, 2017, 11:42 AM
 */

#ifndef WINHELPER_H
#define WINHELPER_H

#include "panda/plugin.h"

#include "dbgdefs.h"

//#include "osi_process.h"
#include <stdint.h>

namespace panda {
    namespace win {
        
//#if defined(TARGET_I386)
//        typedef uint32_t ptr_t;
//        
//#elif defined(TARGET_ARM)
//        typedef uint32_t ptr_t;
//        
//#else
//        typedef uint64_t ptr_t;
//        
//#endif
//        
//        typedef uint32_t pid_t;
//        /**
//         * Obtain the Directory Table Base (DTB) from EPROCESS struct pointed to by eproc
//         * @param env
//         * @param eproc pointer to EPROCESS
//         * @return 
//         */
//        ptr_t get_dtb(CPUState *env, ptr_t eproc);
//        
//        /**
//         * Checks whether the process is valid
//         * @param env
//         * @param eproc
//         * @return 
//         */
//        bool is_valid_process(CPUState *env, ptr_t eproc);
//        
//        /**
//         * Get process ID of given EPROCESS
//         * @param env
//         * @param eproc
//         * @return 
//         */
//        pid_t get_pid(CPUState *env, ptr_t eproc);
//        
//        /**
//         * Get the parent process ID of given EPROCESS
//         * @param env
//         * @param eproc
//         * @return 
//         */
//        pid_t get_ppid(CPUState *env, ptr_t eproc);
//        
//        /**
//         * Get the Process Environment Block (PEB) of given EPROCESS
//         */
//        ptr_t get_peb(CPUState *env, ptr_t eproc);
//        
//        /**
//         * gets the process image file name (NOT FULL PATH)
//         * @param env
//         * @param eproc
//         * @param name OUT parameter
//         */
//        void get_procname(CPUState *env, ptr_t eproc, char *name);
//        
//        /**
//         * Gets the next process at EPROCESS struct pointed to by eproc
//         * via ActiveProcessLinks.FLINK member
//         * This parameter is also a circular linked list.
//         * @param env
//         * @param eproc
//         * @return 
//         */
//        ptr_t get_next_proc(CPUState *env, ptr_t eproc);
//        
//        /**
//         * same like get_next_proc, but uses ActiveProcessLinks.BLINK member
//         * instead of FLINK.
//         * @param env
//         * @param eproc
//         * @return 
//         */
//        ptr_t get_prev_proc(CPUState *env, ptr_t eproc);
//        
//        
//        /**
//         * Obtains the address of KPCR struct via FS register
//         * This is the struct that serves as the gateway to find all
//         * the other kernel structs like EPROCESS, ETHREAD, PEB, and VAD
//         * @param env
//         * @return 
//         */
//        ptr_t get_kpcr(CPUState *env);
//        
//        
//        ptr_t get_current_proc(CPUState *env, ptr_t kpcr = 0);
//        
//        
//        /**         
//         * 
//         * @param env given by PANDA callbacks
//         * @param eproc pointer to eproc struct
//         * @param out the out parameter. It is zeroed out prior usage automatically
//         */
//        void fill_OsiProcess(CPUState *env, ptr_t eproc, OsiProcess &out);
//        
//        
//        /**
//         * Finds ntoskrnl base via idlethread pointer.
//         * This is located from FS register which points to KPCR
//         * From KPCR, locates KPCRB struct and idlethread pointer is there.
//         * @param env
//         * @return 
//         */
//        target_ulong find_ntoskrnl_base_addr_via_idlethread(CPUState *env);
        
        
        target_ulong get_pid(CPUState *env);
        
        target_ulong get_tid(CPUState *env);
        
        
        /**
         * Finds the image that contains the address at start_search
         * @param env
         * @param start_search
         * @return 
         */
        target_ulong find_image_base_addr(CPUState *env, target_ulong start_search);
        
        /**
         * Reads zero-terminated wide (2 byte) character string from guest.
         * @param cpu
         * @param buf
         * @param maxlen
         * @param guest_addr
         * @return 
         */
        uint32_t guest_wzstrncpy(CPUState *cpu, uint16_t *buf, size_t maxlen, target_ulong guest_addr);
        
        /**
         * Reads zero-terminated single byte character string from guest
         * @param cpu
         * @param buf
         * @param maxlen
         * @param guest_addr
         * @return 
         */
        uint32_t guest_zstrncpy(CPUState *cpu, char *buf, size_t maxlen, target_ulong guest_addr);
        
        
        /**
         * Reads possibly non zero-terminated wide (2 byte) character string from guest.
         * @param cpu
         * @param buf
         * @param nRead is number of characters read
         * @param guest_addr
         * @return 
         */
        uint32_t guest_wbstrncpy(CPUState *cpu, uint16_t *buf, int nRead, target_ulong guest_addr);
        
        /**
         * Reads possibly non zero-terminated single byte character string from guest
         * @param cpu
         * @param buf
         * @param nRead is number of characters read
         * @param guest_addr
         * @return 
         */
        uint32_t guest_bstrncpy(CPUState *cpu, char *buf, int nRead, target_ulong guest_addr);
        
    }
}


#endif /* WINHELPER_H */

