/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "entropy_heur.h"
#include "types.h"

#include "heur_util.h"
#include "panda/plugin.h"
#include "panda/common.h"

#include <vector>
using std::vector;

namespace unpacker {
    namespace heuristics {
        namespace entropy {
            
            EntropyHeuristic::EntropyHeuristic()
            : m_prev_entropy(-1.0) {
                
            }
            
            EntropyHeuristic::~EntropyHeuristic() {
                
            }
            
            
            double EntropyHeuristic::eval(unpacker::ProcessInfo& proc, void * opaque) {
                
                // just look at the main exe image now
                // should include dynamic memory buffers also
                
                CPUState * cpu = reinterpret_cast<CPUState*>(opaque);
                
                // obtain buffer
                types::addr_t base_addr = proc.get_module().get_base_addr();
                uint32_t img_size = proc.get_module().get_image_size();
                
                vector<uint8_t> vbuf(img_size + 10);
                if (-1 == panda_virtual_memory_read(cpu, base_addr, &vbuf[0], img_size)) {
                    return 0.0;
                }
                
                double current_entropy = unpacker::heuristics::shannon_entropy(&vbuf[0], img_size);
                
                if (this->m_prev_entropy < 0.0) {
                    this->m_prev_entropy = current_entropy;
                    return 0.0;
                }
                
                // check this with tests
                if (this->m_prev_entropy - current_entropy >= 1.5) {
                    return 1.0;
                }
                
                return 0.0;
                
            }
            
        }
    }
}
