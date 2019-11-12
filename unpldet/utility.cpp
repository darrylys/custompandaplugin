/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "utility.h"

#include <cstring>
#include <cmath>

#include <capstone/capstone.h>

#include "panda/plugin.h"

#if defined(TARGET_I386)
#include <capstone/x86.h>
#elif defined(TARGET_ARM)
#include <capstone/arm.h>
#endif

namespace utility {
    
    void tally1byte(const uint8_t *data, int size, int * out) {
        memset(out, 0, 256*sizeof(int));
        
        for (int i=0; i<size; ++i) {
            out[data[i]]++;
        }
    }
    
    double entropy(const uint8_t *data, int size) {
        
        if (data == NULL || size <= 0) {
            return -1.0;
        }
        
        int tally[256];
        tally1byte(data, size, tally);
        
        double ent = 0.0;
        double px;
        for (int i=0; i<256; ++i) {
            
            if (tally[i] > 0) {
                px = ((double)tally[i]) / size;
                ent += -px * log2(px);
            }
            
        }
        
        return ent;
    }
    
    double chisquare(const uint8_t *data, int size) {
        
        // chisquare test is appropriate if expected value of a cell is >= 5
        // 5*256 = 1280. if ANY is less, use other tests.
        if (data == NULL || size < 1280) {
            return -1.0;
        }
        
        int tally[256];
        tally1byte(data, size, tally);
        
        double expected = size / 256.0;
        double chisq = 0.0;
        
        for (int i=0; i<256; ++i) {
            chisq += ((tally[i] - expected) * (tally[i] - expected)) / expected;
        }
        
        return chisq;
    }
    
    /**
     * Internal class, don't use
     */
    class DisassemblerImpl {
        
    public:
        DisassemblerImpl() { 
        }
        
        ~DisassemblerImpl() {
            cs_close(&this->m_handle);
        }
        
        bool init() {
                        
#if defined(TARGET_I386)
            if (!cs_open(CS_ARCH_X86, CS_MODE_32, &this->m_handle)) {
#elif defined(TARGET_X86_64)
            if (!cs_open(CS_ARCH_X86, CS_MODE_64, &this->m_handle)) {
#elif defined(TARGET_ARM)
            if (!cs_open(CS_ARCH_ARM, CS_MODE_32, &this->m_handle)) {
#else
#error "ERROR! Unknown architecture."
#endif
                return false;
            }
            
            return true;
        }
        
        bool disasm(FILE *out, const uint8_t *code, uint32_t size, uint64_t addr) {
            
            cs_insn * insn;
            
            size_t count = cs_disasm(this->m_handle, code, size, addr, 0, &insn);
            
            if (count > 0) {
                
                fprintf(out, "\nDISASSEMBLY:\n");
                for (uint32_t i=0; i<count; ++i) {
                    fprintf(out, "0x%016lx:\t%s\t\t%s\n", insn[i].address, insn[i].mnemonic, insn[i].op_str);
                }
                
                cs_free(insn, count);
                
            } else {
                fprintf(out, "\nERROR: Failed to disassemble!\n");
                return false;
            }
            
            return true;
        }
        
        
    private:
        
        csh m_handle;
        
    };
    
    
    // PROXY CLASS
    
    /**
     * Construct disassembler. Call init after this
     */
    Disassembler::Disassembler() {
        this->m_impl = new DisassemblerImpl();
    }
    
    Disassembler::~Disassembler() {
        delete this->m_impl;
    }
    
    bool Disassembler::disasm(FILE* out, const void* code, uint32_t size, uint64_t addr) {
        return this->m_impl->disasm(out, (uint8_t*)code, size, addr);
    }

    bool Disassembler::init() {
        return this->m_impl->init();
    }
}
