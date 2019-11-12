/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "StringMetaData.h"
#include "StructData.h"

namespace WinApiLib {

    StructData::StructData(StructMetaData &metadata)
    : CommonData(metadata) {

    }

    StructData::~StructData() {
    }
    
    bool StructData::getBytesFromHost(void * cpu, const uint8_t * pDataInHost, uint8_t outBuf[],
                int outBufLen, int &actualLen, int nBytesRead) {
        
        StructMetaData &pMetadata = reinterpret_cast<StructMetaData&>(this->getMetaData());
        int size = pMetadata.getSize();
        if (nBytesRead) {
            size = nBytesRead;
        }
        
        if (outBuf == NULL || outBufLen < size) {
            actualLen = size;
            return false;
        }
        
        for (int i=0; i<size; ++i) {
            outBuf[i] = *(pDataInHost+i);
        }

        actualLen = size;
        return true;
        
    }

    bool StructData::getBytes(void * cpu, uint64_t addr, uint8_t outBuf[], 
                int outBufLen, int &actualLen, int nBytesRead) {

        StructMetaData &rMetadata = reinterpret_cast<StructMetaData&>(this->getMetaData());
        int size = rMetadata.getSize();
        if (nBytesRead) {
            size = nBytesRead;
        }
        
        if (outBuf == NULL || outBufLen < size) {
            actualLen = size;
            return false;
        }
        
        if (IEnv::S_OK != rMetadata.getEnv().readEnv(addr, 
                outBuf, size, cpu)) {
            actualLen = size;
            return false;
        }

        actualLen = size;
        return true;
    }
}