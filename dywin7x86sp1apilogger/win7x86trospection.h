/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   win7x86trospection.h
 * Author: darryl
 *
 * Created on November 24, 2018, 3:12 PM
 */

#ifndef WIN7X86TROSPECTION_H
#define WIN7X86TROSPECTION_H

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"
#include "panda/plog.h"
#include "panda/rr/rr_log.h"

#include "win7x86osi_types.h"

namespace panda {
    namespace win {
        
        bool init_system();
        
        OsiProc * get_current_process(CPUState *cpu);
        OsiModules * get_libraries(CPUState * cpu, OsiProc *proc);
        
        void free_osiproc(OsiProc *p);
        void free_osiprocs(OsiProcs *ps);
        void free_osimodules(OsiModules *ms);
    }
}

#endif /* WIN7X86TROSPECTION_H */

