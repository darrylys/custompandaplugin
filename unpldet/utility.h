/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   utility.h
 * Author: darryl
 *
 * Created on May 5, 2017, 4:31 PM
 */

#ifndef UTILITY_H
#define UTILITY_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

namespace utility {
    
    /**
     * Computes entropy of given data based on Shannon. the larger, the more accurate.
     * 
     * @param data
     * @param size
     * @return -1 if error, [0.0 , 8.0] otherwise
     */
    double entropy(const uint8_t *data, int size);
    
    /**
     * Computes chisquare of given data.
     * 
     * @param data
     * @param size, minimum 1280
     * @return -1 if error.
     */
    double chisquare(const uint8_t *data, int size);
    
    class DisassemblerImpl;
    
    class Disassembler {
    public:
        Disassembler();
        ~Disassembler();

        bool init();
        
        bool disasm(FILE *out, const void *code, uint32_t size, uint64_t addr);
        
    private:
        DisassemblerImpl * m_impl;
        
    };
    
}

#endif /* UTILITY_H */

