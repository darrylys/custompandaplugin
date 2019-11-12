/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "ArithmeticFilter.h"
#include <stdint.h>

#include <string.h>

#include <capstone/capstone.h>

#if defined(TARGET_I386)
#include <capstone/x86.h>
#elif defined(TARGET_ARM)
#include <capstone/arm.h>
#endif

const char * const ArithmeticFilter::ARITH_MNEMONIC[7] = {
    "add", "sub", "mul", "imul", "div", "idiv", NULL
};

ArithmeticFilter::ArithmeticFilter() {

}

ArithmeticFilter::~ArithmeticFilter() {
    
}

const char * ArithmeticFilter::getName() {
    return "Arithmetic";
}

double ArithmeticFilter::analyse(void* v) {
    ProcParam* pProcParam = reinterpret_cast<ProcParam*>(v);
    size_t count = pProcParam->count;
    cs_insn* insn = pProcParam->insn;
    
    uint32_t nArith = 0;
    for (size_t j = 0; j < count; j++) {
        for (int k=0; ARITH_MNEMONIC[k] != NULL; ++k) {
            if (strcasecmp(ARITH_MNEMONIC[k], insn[j].mnemonic) == 0) {
                // check if this writes to memory.
                
                bool writeToMemory = false;
                cs_detail* detail = insn[j].detail;
                if (detail != NULL) {
                    cs_x86_op op0 = detail->x86.operands[0];
                    if (op0.type == X86_OP_MEM/* && op0.mem.disp == 0*/) {
                        // removing check displacement, not required & too restrictive. 
                        writeToMemory = true;
                    }
                }
                
                if (writeToMemory) {
                    nArith++;
                }
                break;
            }
        }
    }
    
//    double ratio = (double)nArith / count;
//    if (ratio >= 0.4) {
//        return 1.0;
//    } else {
//        return 0.0;
//    }
    
    if (nArith > 0) {
        return 1.0;
    } else {
        return 0.0;
    }
    
}

