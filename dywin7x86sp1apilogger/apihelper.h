/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   apihelper.h
 * Author: darryl
 *
 * Created on November 20, 2018, 10:39 AM
 */

#ifndef APIHELPER_H
#define APIHELPER_H

/**
 * Reads the function parameter from stack
 * Only tested for TARGET_I386, Windows 7 x86 SP1
 * 
 * @param cpu, the CPUState* from qemu
 * @param offset, the offset from address of return address in esp which points to parameter
 * @param out buf, buffer out
 * @param bufsize, the size of buf in bytes
 * 
 * @return 0 if fail, 1 if success
 * 
 */
int get_func_param(CPUState *cpu, target_ulong offset, void * buf, int bufsize);

/**
 * 
 */
target_ulong get_func_param_addr(CPUState *cpu, target_ulong offset);

#endif /* APIHELPER_H */

