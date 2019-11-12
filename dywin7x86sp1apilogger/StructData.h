/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   StructData.h
 * Author: darryl
 *
 * Created on November 3, 2018, 3:05 PM
 */

#ifndef STRUCTDATA_H
#define STRUCTDATA_H

#include "IWinTypes.h"
#include "IWinTypeMetaData.h"
#include "StructMetaData.h"
#include "CommonData.h"

namespace WinApiLib {
    class StructData : public CommonData {
    public:
        StructData(StructMetaData &metadata);
        ~StructData();
        bool getBytes(void * cpu, uint64_t addr, uint8_t outBuf[], 
                int outBufLen, int &actualLen, int nBytesRead = 0);
        bool getBytesFromHost(void * cpu, const uint8_t * pDataInHost, uint8_t outBuf[],
                int outBufLen, int &actualLen, int nBytesRead = 0);
    };
}

#endif /* STRUCTDATA_H */

