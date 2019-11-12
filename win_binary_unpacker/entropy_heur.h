/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   entropy_heur.h
 * Author: darryl
 *
 * Created on August 12, 2017, 3:07 PM
 */

#ifndef ENTROPY_HEUR_H
#define ENTROPY_HEUR_H

#include "IHeuristics.h"

namespace unpacker {
    namespace heuristics {
        namespace entropy {
            
            class EntropyHeuristic : public unpacker::heuristics::IHeuristics {
            public:
                EntropyHeuristic();
                virtual ~EntropyHeuristic();
                
                virtual double eval(unpacker::ProcessInfo&, void * opaque);
                
            private:
                double m_prev_entropy;
                
            };
            
        }
    }
}

#endif /* ENTROPY_HEUR_H */

