/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   ShiftFilter.h
 * Author: darryl
 *
 * Created on January 12, 2019, 7:46 PM
 */

#ifndef SHIFTFILTER_H
#define SHIFTFILTER_H

#include "IProcFilter.h"
#include "ProcParam.h"

#include <stdint.h>

class ShiftFilter : public IProcFilter {
public:
    ShiftFilter();
    ~ShiftFilter();
    double analyse(void * v);
    const char * getName();
    
private:
    static const char * const SHIFT_MNEMONIC[7];
    
};


#endif /* SHIFTFILTER_H */

