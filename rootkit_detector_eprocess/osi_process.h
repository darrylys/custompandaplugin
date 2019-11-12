/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   osi_process.h
 * Author: darryl
 *
 * Created on April 27, 2017, 11:11 AM
 */

#ifndef OSI_PROCESS_H
#define OSI_PROCESS_H

#include<stdio.h>
#include<string>

using std::string;

typedef uint64_t ADDR;
typedef uint32_t PID;

typedef struct _OSI_PROCESS {
    
    ADDR eproc;
    string imageName;
    ADDR asid;
    PID pid;
    PID ppid;
    
} OsiProcess;

void dump_OsiProcess(FILE * file, const OsiProcess &in) {
    fprintf(file, "OsiProcess {\n");
    
    fprintf(file, "\teproc: %016lx\n", in.eproc);
    fprintf(file, "\timageName: '%s'\n", in.imageName.c_str());
    fprintf(file, "\tasid: %016lx\n", in.asid);
    fprintf(file, "\tpid: 0x%08x (%u)\n", in.pid, in.pid);
    fprintf(file, "\tppid: 0x%08x (%u)\n", in.ppid, in.ppid);
    
    fprintf(file, "}\n");
}

#endif /* OSI_PROCESS_H */

