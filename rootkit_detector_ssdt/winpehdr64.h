/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   winpehdr64.h
 * Author: darryl
 *
 * Created on May 15, 2017, 10:04 AM
 */

#ifndef WINPEHDR64_H
#define WINPEHDR64_H


#include <stdio.h>

// better make it functions

#define WINPE_DEBUG

namespace winpe {

    
typedef uint64_t peaddr_t;
    
class WinPE {
public:
    WinPE(peaddr_t pe_base, FILE * dump_file);
    WinPE(peaddr_t pe_base);
    virtual ~WinPE();

    // get the lowest address of pe image
    peaddr_t get_low_addr();

    // get the highest address (inclusive) of pe image
    peaddr_t get_high_addr();

    /**
     * Get the address of exported function. Parsed from PE Header export table
     * @param export_fn_name
     * @return 0 if export not found, the address otherwise
     */
    peaddr_t get_export_func(const char * export_fn_name);

protected:
    /**
     * Reads memory from some source. This is to be implemented by subclasses
     * @param src address of source
     * @param out 
     * @param size in and out.
     * @return number of bytes read, 0 if fails.
     */
    virtual int read_mem(peaddr_t src, uint8_t *out, int size) = 0;
    
private:
    peaddr_t m_pe_base;
    
    peaddr_t _get_opthdr_off();
    bool _read_image_opt_hdr(peaddr_t off, uint8_t *out, int size);
    
    FILE * m_dump;
    
}; // class WinPE


}; // namespace winpe

#endif /* WINPEHDR64_H */

