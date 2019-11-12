/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   IEnv.h
 * Author: darryl
 *
 * Created on November 4, 2018, 4:04 PM
 */

#ifndef IENV_H
#define IENV_H

#include <stdint.h>

namespace WinApiLib {
    
    /**
     * Interface to represent environment where the system can read from and write to (for now).
     * Can be added for more function to allow more interaction
     */
    class IEnv {
    public:
        /**
         * Return value OK for operations in IEnv interface
         */
        static const int S_OK = 0;
        
        /**
         * Return value general ERR for operations in IEnv interface
         */
        static const int E_ERR = -1;
        
        IEnv(){}
        virtual ~IEnv(){}
    
        /**
         * Method to read from environment
         * @param addr address to begin reading
         * @param buf out buffer
         * @param len length of out buffer
         * @param extra, extra object to pass.
         */
        virtual int readEnv(uint64_t addr, uint8_t * buf, int len, void * extra) = 0;
        
        /**
         * Method to write to environment
         * @param addr address to begin writing
         * @param buf out buffer
         * @param len length of out buffer
         * @param extra, extra object to pass.
         */
        virtual int writeEnv(uint64_t addr, uint8_t * buf, int len, void * extra) = 0;

        // probably need adding more functions

    };
}

#endif /* IENV_H */

