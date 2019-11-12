/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "utils.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

namespace utils {
    
    uint32_t hex2uint(const char * strHex) {
        uint32_t ii;
        sscanf(strHex, "%x", &ii);
        return ii;
    }
    
    uint64_t hex2ulong(const char * strHex) {
        uint64_t ii;
        sscanf(strHex, "%lx", &ii);
        return ii;
    }
    
    /**
     * Convenience method to convert string representation of decimal or hex to int
     * @param strNum
     * @return uint32_t 
     */
    uint32_t str2uint(const char * strNum) {
        if (strNum[0] == '0' && (strNum[1] == 'x' || strNum[1] == 'X')) {
            return hex2uint(strNum);
        } else {
            return atoi(strNum);
        }
    }
    
}
