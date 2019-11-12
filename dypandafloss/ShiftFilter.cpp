/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "ShiftFilter.h"
#include <stdint.h>

#include <string.h>

#include <capstone/capstone.h>

#if defined(TARGET_I386)
#include <capstone/x86.h>
#elif defined(TARGET_ARM)
#include <capstone/arm.h>
#endif

const char * const ShiftFilter::SHIFT_MNEMONIC[7] = {
    "shl", "shr", "sar", "sal", "rol", "ror", NULL
};

ShiftFilter::ShiftFilter() {

}

ShiftFilter::~ShiftFilter() {
    
}

const char * ShiftFilter::getName() {
    return "Shift";
}

double ShiftFilter::analyse(void* v) {
    ProcParam* pProcParam = reinterpret_cast<ProcParam*>(v);
    size_t count = pProcParam->count;
    cs_insn* insn = pProcParam->insn;
    
    uint32_t shifts = 0;
    int shiftSize = 0;
    
    for (size_t j = 0; j < count; j++) {
        // check shl, shr, sar, sal, ror, rol
        // "shl", "shr", "sar", "sal", "rol", "ror"
        for (int k=0; SHIFT_MNEMONIC[k] != NULL; ++k) {
            if (strcasecmp(SHIFT_MNEMONIC[k], insn[j].mnemonic) == 0) {
                shifts |= (1<<k);
                break;
            }
            shiftSize++;
        }
    }
    
    uint32_t ones = 0;
    while (shifts) {
        ones += (shifts&1);
        shifts >>= 1;
    }
    return (double)ones / shiftSize;
}
