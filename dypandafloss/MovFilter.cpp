/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "MovFilter.h"
#include <stdint.h>

#include <string.h>

#include <capstone/capstone.h>

#if defined(TARGET_I386)
#include <capstone/x86.h>
#elif defined(TARGET_ARM)
#include <capstone/arm.h>
#endif

MovFilter::MovFilter() {
    
}

MovFilter::~MovFilter() {

}

const char * MovFilter::getName() {
    return "Mov";
}

double MovFilter::analyse(void* v) {
    ProcParam* pProcParam = reinterpret_cast<ProcParam*>(v);
    size_t count = pProcParam->count;
    cs_insn* insn = pProcParam->insn;
    
    uint32_t nMov = 0;
    for (size_t j = 0; j < count; j++) {
        
        cs_detail* detail = insn[j].detail;
        
        // check mov
        if (strcasecmp("mov", insn[j].mnemonic) == 0) {

            bool countMov = false;
            // must mov from register to memory / memory to memory,
            if (detail != NULL) {
                cs_x86_op op0 = detail->x86.operands[0];
                if (op0.type == X86_OP_MEM/* && op0.mem.disp == 0*/) {
                    // removing check displacement, not required & too restrictive. 
                    countMov = true;
                }
            }

            if (countMov) {
                fprintf(stderr, "[debug] --- Find Mov\n");
                nMov++;
            }
        }
    }
    
    return nMov;
}
