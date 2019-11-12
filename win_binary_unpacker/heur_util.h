/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   heur_util.h
 * Author: darryl
 *
 * Created on July 30, 2017, 10:51 PM
 */

#ifndef HEUR_UTIL_H
#define HEUR_UTIL_H

#include <cstdint>

namespace unpacker {
    namespace heuristics {
        
        double shannon_entropy(const uint8_t *buf, int len);
        
        double chisq(const uint8_t *buf, int len);
        
        int count_ngram(uint8_t * buf, int len, uint8_t * ch_match, bool * is_wildcard, int chlen);
        
    }
}

#endif /* HEUR_UTIL_H */

