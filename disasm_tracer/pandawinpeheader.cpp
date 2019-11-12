/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "pandawinpeheader.h"


namespace winpe {
    
    WinPEPanda::WinPEPanda(CPUState* env, peaddr_t pe_base, FILE * debug_file)
        : WinPE(pe_base, debug_file), m_env(env)
    {
    }
    
    WinPEPanda::~WinPEPanda() {
        
    }
    
    int WinPEPanda::read_mem(peaddr_t src, uint8_t *out, int size) {
        if (-1 == panda_virtual_memory_read(m_env, src, out, size)) {
            return 0;
        }
        return size;
    }
    
}
