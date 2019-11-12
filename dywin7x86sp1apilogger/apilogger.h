/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   apilogger.h
 * Author: darryl
 *
 * Created on November 20, 2018, 10:41 AM
 */

#ifndef APILOGGER_H
#define APILOGGER_H

#include "panda/plugin.h"                                    
#include "panda/common.h"             

#include <string>
#include "dbgdefs.h"

bool apilogger_init(const char * typesCsvSource, const char * fnApiCsvSource);

const char * apilogger_find_func(CPUState * cpu, const char * dllName, 
        target_ulong pc, target_ulong dllBaseAddr);

bool apilogger_log_call(CPUState * cpu, target_ulong pc, const char * dllName, 
        target_ulong dllBaseAddr, const char * funcName, std::string& out);

bool apilogger_log_return(CPUState * cpu, target_ulong pc, const char * dllName, 
        target_ulong dllBaseAddr, const char * funcName, std::string& out);

void apilogger_close();

#endif /* APILOGGER_H */

