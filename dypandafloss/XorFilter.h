/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   XorFilter.h
 * Author: darryl
 *
 * Created on January 12, 2019, 7:34 PM
 */

#ifndef XORFILTER_H
#define XORFILTER_H

#include "IProcFilter.h"
#include "ProcParam.h"

class XorFilter : public IProcFilter {
public:
    XorFilter();
    ~XorFilter();
    double analyse(void * v);
    const char * getName();
    
};

#endif /* XORFILTER_H */

