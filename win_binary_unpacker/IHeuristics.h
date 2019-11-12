/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   IHeuristics.h
 * Author: darryl
 *
 * Created on August 2, 2017, 11:53 PM
 */

#ifndef IHEURISTICS_H
#define IHEURISTICS_H

namespace unpacker {
    
    class ProcessInfo;
    
    namespace heuristics {
        class IHeuristics {
        public:
            IHeuristics() {
                
            }
            
            virtual ~IHeuristics() {
                
            }
            
            virtual double eval(unpacker::ProcessInfo& proc, void * opaque = 0) = 0;
            
        };
    }
}

#include "proc_info.h"

#endif /* IHEURISTICS_H */

