/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "XorFilter.h"
#include <stdint.h>

#include <string.h>

#include <capstone/capstone.h>

#if defined(TARGET_I386)
#include <capstone/x86.h>
#elif defined(TARGET_ARM)
#include <capstone/arm.h>
#endif

XorFilter::XorFilter() {
    
}

XorFilter::~XorFilter() {
    
}

const char * XorFilter::getName() {
    return "Xor";
}

double XorFilter::analyse(void* v) {
    ProcParam* pProcParam = reinterpret_cast<ProcParam*>(v);
    size_t count = pProcParam->count;
    cs_insn* insn = pProcParam->insn;
    
    uint32_t nXor = 0;
    for (size_t j = 0; j < count; j++) {
        
        cs_detail* detail = insn[j].detail;
        
        // check non-zero XOR
        if (strcasecmp("xor", insn[j].mnemonic) == 0) {
            // exclude zero-in xors, such as xor eax, eax and so on.
            bool countXor = true;
            if (detail != NULL) {
                uint32_t opCount = detail->x86.op_count;
                fprintf(stderr, "[debug] -- opCount: %u\n", opCount);
                if (opCount == 2) {
                    cs_x86_op op0 = detail->x86.operands[0];
                    cs_x86_op op1 = detail->x86.operands[1];
                    if (op0.type == X86_OP_REG && op1.type == X86_OP_REG &&
                        op0.reg == op1.reg) {
                        countXor = false;
                    }
                }
            }

            if (countXor) {
                fprintf(stderr, "[debug] --- Find Xor\n");
                nXor++;
            }
        }
    }
    
    if (nXor > 0) {
        return 1.0;
    } else {
        return 0.0;
    }
}