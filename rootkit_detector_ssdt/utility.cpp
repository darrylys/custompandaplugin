/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "utility.h"

#include <cstring>
#include <cmath>


namespace utility {
    
    void tally1byte(const uint8_t *data, int size, int * out) {
        memset(out, 0, 256*sizeof(int));
        
        for (int i=0; i<size; ++i) {
            out[data[i]]++;
        }
    }
    
    double entropy(const uint8_t *data, int size) {
        
        if (data == NULL || size <= 0) {
            return -1.0;
        }
        
        int tally[256];
        tally1byte(data, size, tally);
        
        double ent = 0.0;
        double px;
        for (int i=0; i<256; ++i) {
            
            if (tally[i] > 0) {
                px = ((double)tally[i]) / size;
                ent += -px * log2(px);
            }
            
        }
        
        return ent;
    }
    
    double chisquare(const uint8_t *data, int size) {
        
        // chisquare test is appropriate if expected value of a cell is >= 5
        // 5*256 = 1280. if ANY is less, use other tests.
        if (data == NULL || size < 1280) {
            return -1.0;
        }
        
        int tally[256];
        tally1byte(data, size, tally);
        
        double expected = size / 256.0;
        double chisq = 0.0;
        
        for (int i=0; i<256; ++i) {
            chisq += ((tally[i] - expected) * (tally[i] - expected)) / expected;
        }
        
        return chisq;
    }
    
}
