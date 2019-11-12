/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "jump_to_text_heur.h"

//#include "panda/plugin.h"
//#include "panda/common.h"

namespace unpacker {
    namespace heuristics {
        namespace longjmp {
           
            JumpHeuristic::JumpHeuristic() 
            : m_prev_eip(0) {
                
            }
            
            JumpHeuristic::~JumpHeuristic() {
                
            }
            
            double JumpHeuristic::eval(unpacker::ProcessInfo&, void* opaque) {
                //CPUState * env = reinterpret_cast<CPUState*>(opaque);
                
                // check:
                // 1. long jumps
                // 2. cross section jump
                // 3. jump return to .text section
                
                return 0.0;
            }
            
        }
    }
}
