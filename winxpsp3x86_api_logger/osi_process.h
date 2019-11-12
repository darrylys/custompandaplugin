/*
 * TODO: Combine this to winhelper.h
 */

/* 
 * File:   osi_process.h
 * Author: darryl
 *
 * Created on April 27, 2017, 11:11 AM
 */

#ifndef OSI_PROCESS_H
#define OSI_PROCESS_H

#include "panda/plugin.h"

#include<stdio.h>
#include<string>

using std::string;
using std::wstring;

typedef uint32_t PID;

#if defined(TARGET_I386)
typedef uint32_t ADDRINT;
#elif defined(TARGET_ARM)
typedef uint32_t ADDRINT;
#elif defined(TARGET_X86_64)
typedef uint64_t ADDRINT;
#endif

//typedef uint64_t ADDR64;
//typedef uint32_t PID;
//typedef uint32_t ADDR32;
//
//#if defined(TARGET_I386)
//typedef ADDR32 ADDRINT;
//#elif defined(TARGET_ARM)
//typedef ADDR32 ADDRINT;
//#else
//typedef ADDR64 ADDRINT;
//#endif

typedef struct _OSI_MODULE {
    
    ADDRINT offset;
    ADDRINT base;
    ADDRINT ep;
    uint32_t size;
    string full_dll_name;
    string base_dll_name;
    
} OsiModule;

typedef struct _OSI_PROCESS {
    
    ADDRINT eproc;
    string imageName;
    ADDRINT asid;
    PID pid;
    PID ppid;
    
} OsiProcess;

void dump_OsiModule(FILE *file, const OsiModule &in);

void dump_OsiProcess(FILE * file, const OsiProcess &in);

#endif /* OSI_PROCESS_H */

