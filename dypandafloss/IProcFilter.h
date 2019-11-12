/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   IProcFilter.h
 * Author: darryl
 *
 * Created on January 12, 2019, 7:30 PM
 */

#ifndef IPROCFILTER_H
#define IPROCFILTER_H

class IProcFilter {
public:
    IProcFilter() {}
    virtual ~IProcFilter() {}
    virtual double analyse(void * v) = 0;
    virtual const char * getName() = 0;
    
};

#endif /* IPROCFILTER_H */

