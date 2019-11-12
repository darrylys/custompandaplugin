/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   ProcParam.h
 * Author: darryl
 *
 * Created on January 12, 2019, 7:41 PM
 */

#ifndef PROCPARAM_H
#define PROCPARAM_H

#include <capstone/capstone.h>

#if defined(TARGET_I386)
#include <capstone/x86.h>
#elif defined(TARGET_ARM)
#include <capstone/arm.h>
#endif

typedef struct _ProcParam {
    cs_insn* insn;
    size_t count;
} ProcParam;

#endif /* PROCPARAM_H */

