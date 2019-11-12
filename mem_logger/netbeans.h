/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   netbeans.h
 * Author: darryl
 *
 * Created on July 30, 2017, 2:44 PM
 */

#ifndef NETBEANS_H
#define NETBEANS_H

//#define NETBEANS

#ifdef NETBEANS
#include "exec/cpu-all.h"
typedef uint64_t target_ulong;
#endif

#endif /* NETBEANS_H */

