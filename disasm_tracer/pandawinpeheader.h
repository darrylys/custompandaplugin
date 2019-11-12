/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   pandawinpeheader.h
 * Author: darryl
 *
 * Created on May 20, 2017, 1:44 PM
 */

#ifndef PANDAWINPEHEADER_H
#define PANDAWINPEHEADER_H

#include "panda/plugin.h"

#if defined(TARGET_I386)
#include "winpehdr.h"
#elif defined(TARGET_X86_64)
#include "winpehdr.h" // change this to 64 version later
#elif defined(TARGET_ARM)
#include "winpehdr.h"
#endif

#include <stdio.h>

namespace winpe {
    class WinPEPanda : public WinPE {
    public:
        WinPEPanda(CPUState *env, peaddr_t pe_base, FILE * debug_file);
        ~WinPEPanda();
        
    protected:
        virtual int read_mem(peaddr_t src, uint8_t *out, int size);
        
    private:
        CPUState * m_env;
    };
}

#endif /* PANDAWINPEHEADER_H */

