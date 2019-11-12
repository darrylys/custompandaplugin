/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   IProcDumper.h
 * Author: darryl
 *
 * Created on August 14, 2017, 4:37 PM
 */

#ifndef IPROCDUMPER_H
#define IPROCDUMPER_H

namespace unpacker {
    
    class ProcessInfo;
    
    namespace dumper {
        class IProcDumper {
        public:
            IProcDumper() {
                
            }
            
            virtual ~IProcDumper() {
                
            }
            
            virtual void dump(unpacker::ProcessInfo&) = 0;
        };
    }
}

#include "proc_info.h"

#endif /* IPROCDUMPER_H */

