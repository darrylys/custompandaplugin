/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   ArithmeticFilter.h
 * Author: darryl
 *
 * Created on January 12, 2019, 8:00 PM
 */

#ifndef ARITHMETICFILTER_H
#define ARITHMETICFILTER_H

#include "IProcFilter.h"
#include "ProcParam.h"

class ArithmeticFilter : public IProcFilter {
public:
    ArithmeticFilter();
    ~ArithmeticFilter();
    double analyse(void * v);
    const char * getName();
    
private:
    static const char * const ARITH_MNEMONIC[7];
};

#endif /* ARITHMETICFILTER_H */

