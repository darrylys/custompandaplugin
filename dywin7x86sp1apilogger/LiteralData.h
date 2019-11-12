/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   LiteralData.h
 * Author: darryl
 *
 * Created on November 3, 2018, 2:57 PM
 */

#ifndef LITERALDATA_H
#define LITERALDATA_H

#include "IWinTypes.h"
#include "IWinTypeMetaData.h"
#include "CommonData.h"
#include "LiteralMetaData.h"

namespace WinApiLib {
    class LiteralData : public CommonData {    
    public:
        LiteralData(LiteralMetaData &metadata);
        ~LiteralData();
        bool getBytes(void * cpu, uint64_t addr, uint8_t outBuf[], 
                int outBufLen, int &actualLen, int nBytesRead = 0);
        bool getBytesFromHost(void * cpu, const uint8_t * pDataInHost, uint8_t outBuf[],
                int outBufLen, int &actualLen, int nBytesRead = 0);
        
    };
}
#endif /* LITERALDATA_H */

