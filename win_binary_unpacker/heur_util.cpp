/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */


#include "heur_util.h"

#include <cstring>
#include <cmath>

namespace unpacker {
    namespace heuristics {
        
        const double D1LOG2 = 1.4426950408889634073599246810023;
        
        double shannon_entropy(const uint8_t *buf, int len) {
            
            double entropy = -1.0;
            
            if (buf != NULL) {
            
                int tally[256];
                memset(tally, 0, sizeof(tally));

                for (int i=0; i<len; ++i) {
                    tally[buf[i]]++;
                }
                
                entropy = 0.0;
                for (int i=0; i<256; ++i) {
                    if (tally[i]) {
                        double t = (double)tally[i] / len;
                        entropy += -t * (log(t)*D1LOG2);
                    }
                }
            }
            
            return entropy;
        }
        
        double chisq(const uint8_t *buf, int len) {
            
            double s = -1.0;
            
            if (buf != NULL) {
                
                int tally[256];
                memset(tally, 0, sizeof(tally));

                for (int i=0; i<len; ++i) {
                    tally[buf[i]]++;
                }
                
                double expected = (double)len / 256.0;
                if (expected <= 5.0) {
                    return s;
                }
                
                s = 0.0;
                for (int i=0; i<256; ++i) {
                    double tmp = (tally[i] - expected);
                    tmp *= tmp;
                    s += tmp / expected;
                }
            }
            
            return s;
        }
        
        int count_ngram(uint8_t * buf, int len, uint8_t * ch_match, bool * is_wildcard, int chlen) {
    
            int sum=0;
            bool match = false;
            for (int i=0; i<len - chlen; ++i) {

                match = true;
                for (int j=i; j<i+chlen; ++j) {
                    if (!is_wildcard[j-i]) {
                        if (buf[j] != ch_match[j-i]) {
                            // not match
                            match = false;
                            break;
                        }
                    }
                }

                if (match) {
                    sum++;
                }

            }

            return sum;

        }
        
    }
}
