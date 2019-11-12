// this is for Win x86 first. for 64-bit, later on

#ifndef WINPEHDR_H
#define WINPEHDR_H

#include <stdio.h>

#include <string>

using std::string;

// better make it functions

//#define WINPE_DEBUG

namespace winpe {

    
typedef uint32_t peaddr_t;
    
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
    
    string get_api_name_from_addr(peaddr_t addr);

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
    FILE * m_dump;
    void * m_ImageOptHeaderPtr;
    
    peaddr_t _get_opthdr_off();
    bool _read_image_opt_hdr(peaddr_t off, uint8_t *out, int size);
    void _init_pe();
    uint8_t *_get_export_data(peaddr_t &virtual_addr, uint32_t &size);
    
    
}; // class WinPE


}; // namespace winpe

#endif
