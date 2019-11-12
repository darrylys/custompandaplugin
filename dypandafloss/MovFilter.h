/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   MovFilter.h
 * Author: darryl
 *
 * Created on January 12, 2019, 7:55 PM
 */

#ifndef MOVFILTER_H
#define MOVFILTER_H

#include "IProcFilter.h"
#include "ProcParam.h"

class MovFilter : public IProcFilter {
public:
    MovFilter();
    ~MovFilter();
    double analyse(void * v);
    const char * getName();
};

#endif /* MOVFILTER_H */

