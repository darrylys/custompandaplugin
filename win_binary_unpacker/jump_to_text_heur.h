/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   jump_to_text_heur.h
 * Author: darryl
 *
 * Created on August 15, 2017, 11:13 PM
 */

#ifndef JUMP_TO_TEXT_HEUR_H
#define JUMP_TO_TEXT_HEUR_H

#include "types.h"
#include "IHeuristics.h"

namespace unpacker {
    namespace heuristics {
        namespace longjmp {
            
            class JumpHeuristic : public unpacker::heuristics::IHeuristics {
            public:
                JumpHeuristic();
                virtual ~JumpHeuristic();
                
                virtual double eval(unpacker::ProcessInfo&, void * opaque);
                
            private:
                types::addr_t m_prev_eip;
                
            };
        
        }
    }
}

#endif /* JUMP_TO_TEXT_HEUR_H */

