/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   loopdetector.h
 * Author: darryl
 *
 * Created on May 2, 2017, 3:58 PM
 */

#ifndef LOOPDETECTOR_H
#define LOOPDETECTOR_H

#include <stdint.h>
#include <stddef.h>

namespace loopdetector {

    namespace types {
        
        typedef uint64_t ADDRINT;
 /*
#if defined (TARGET_I386)
        typedef uint32_t ADDRINT;
#elif defined (TARGET_ARM)
        typedef uint32_t ADDRINT;
#else
        typedef uint64_t ADDRINT;
#endif
   */     
        typedef uint32_t SIZE_T;
        typedef uint16_t WORD;
        typedef uint32_t DWORD;
        typedef uint32_t ULONG;
        typedef int32_t LONG;
        typedef uint8_t BYTE;
        typedef uint64_t QWORD;
        typedef uint64_t ULONGLONG;
        
    }
    
    class LoopDetectorImpl;

    /**
     * Implement this interface as an interface to read to various sources
     * including PANDA
     */
    class EnvironmentAccessor {
    public:
        
        EnvironmentAccessor();
        
        virtual ~EnvironmentAccessor();
        
        int read_mem(types::ADDRINT src, types::BYTE *out, int size);
        
        void debug_print(const char *str);
        
    private:
        /**
         * Reading virtual memory from environment 
         * @param src source address to read from environment
         * @param out out buffer
         * @param size size of buffer
         * @return the size actually written to buffer
         */
        virtual int impl_read_mem(types::ADDRINT src, types::BYTE *out, int size) = 0;
        
        virtual void impl_debug_print(const char * str);
        
        // add more functions if needed
        // like reading registers
        
    };
    
    class LoopDetector {
    public:
        LoopDetector(EnvironmentAccessor * env);
        ~LoopDetector();
        
        void before_ins_exec(types::ADDRINT pc, const char * disasm);
        
        void before_virt_mem_write(types::ADDRINT pc, 
            types::ADDRINT write_addr, void * write_buf, types::SIZE_T write_size);

    private:
        LoopDetectorImpl * m_impl;
        EnvironmentAccessor * m_env;
        
    };
    
}

#endif /* LOOPDETECTOR_H */

