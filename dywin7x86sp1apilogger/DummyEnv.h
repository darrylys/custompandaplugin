/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   DummyEnv.h
 * Author: darryl
 *
 * Created on November 4, 2018, 4:10 PM
 */

#ifndef DUMMYENV_H
#define DUMMYENV_H

#include "IEnv.h"

namespace WinApiLib {
    class DummyEnv : public IEnv {
    public:
        DummyEnv();
        ~DummyEnv();

        int readEnv(uint64_t addr, uint8_t * buf, int len, void * extra);
        int writeEnv(uint64_t addr, uint8_t * buf, int len, void * extra);

    };
}


#endif /* DUMMYENV_H */

