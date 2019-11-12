/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   utils.h
 * Author: darryl
 *
 * Created on November 7, 2018, 11:13 PM
 */

#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stdio.h>

namespace utils {
    
    uint32_t hex2uint(const char * strHex);
    uint64_t hex2ulong(const char * strHex);
    uint32_t str2uint(const char * strNum);
    
}

#endif /* UTILS_H */

