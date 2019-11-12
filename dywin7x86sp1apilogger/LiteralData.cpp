/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "LiteralMetaData.h"
#include "LiteralData.h"

namespace WinApiLib {
    LiteralData::LiteralData(LiteralMetaData &metadata) 
    : CommonData(metadata)
    {

    }

    LiteralData::~LiteralData() {
    }

    bool LiteralData::getBytes(void * cpu, uint64_t addr, uint8_t outBuf[], 
                int outBufLen, int &actualLen, int nBytesRead) {

        LiteralMetaData &pMetadata = reinterpret_cast<LiteralMetaData&>(this->getMetaData());
        int size = pMetadata.getSize();
        if (nBytesRead) {
            size = nBytesRead;
        }
        
        if (outBuf == NULL || outBufLen < size) {
            actualLen = size;
            return false;
        }
        
        IEnv &env = pMetadata.getEnv();
        if (IEnv::S_OK != env.readEnv(addr, outBuf, size, cpu)) {
            actualLen = size;
            return false;
        }

        actualLen = size;
        return true;
    }
    
    bool LiteralData::getBytesFromHost(void * cpu, const uint8_t * pDataInHost, uint8_t outBuf[],
                int outBufLen, int &actualLen, int nBytesRead) {
        
        LiteralMetaData &pMetadata = reinterpret_cast<LiteralMetaData&>(this->getMetaData());
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
}