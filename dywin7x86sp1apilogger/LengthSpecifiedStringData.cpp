/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "StringData.h"
#include <assert.h>

#include <cstdio>

namespace WinApiLib {

    LengthSpecifiedString::LengthSpecifiedString(StringMetaData &metadata)
    : CommonData(metadata) {

    }

    LengthSpecifiedString::~LengthSpecifiedString() {
    }
    
    int LengthSpecifiedString::readNWideFromHost(void *cpu, uint16_t *buf, int nRead, const uint8_t * hostAddr){
        
        buf[0] = 0;
        unsigned i = 0;
        
        for (i = 0; i < nRead; i++) {
            uint16_t tmp = 0;
            uint8_t* ptmp = reinterpret_cast<uint8_t*>(&tmp);
            
            ptmp[0] = *(hostAddr + sizeof(buf[0]) * i);
            ptmp[1] = *(hostAddr + sizeof(buf[0]) * i + 1);
            
            buf[i] = tmp;
        }
        buf[nRead] = 0;
        return i;
        
    }
    
    int LengthSpecifiedString::readNAsciiFromHost(void *cpu, char *buf, int nRead, const uint8_t * hostAddr) {
        
        buf[0] = 0;
        unsigned i = 0;
        
        for (i = 0; i < nRead; i++) {
            buf[i] = (char)(*(hostAddr + i));
        }
        buf[nRead] = 0;
        return i;
        
    }
    
    int LengthSpecifiedString::readNAsciiFromGuest(void* cpu, char* buf, 
            int nRead, uint64_t guest_addr) {
        buf[0] = 0;
        unsigned i = 0;
        
        StringMetaData& rMetadata = reinterpret_cast<StringMetaData&>(this->getMetaData());
        IEnv &env = rMetadata.getEnv();
        
        for (i = 0; i < nRead; i++) {
            if (IEnv::S_OK != env.readEnv(guest_addr + sizeof (buf[0]) * i, 
                    (uint8_t *) & buf[i], sizeof (buf[0]), cpu)) {
                buf[0] = 0;
                return 0;
            }
        }
        buf[nRead] = 0;
        return i;
    }
    
    int LengthSpecifiedString::readNWideFromGuest(void* cpu, uint16_t* buf, 
            int nRead, uint64_t guest_addr) {
        buf[0] = 0;
        unsigned i = 0;
        
        StringMetaData& rMetadata = reinterpret_cast<StringMetaData&>(this->getMetaData());
        IEnv &env = rMetadata.getEnv();
        
        for (i = 0; i < nRead; i++) {
            if (IEnv::S_OK != env.readEnv(guest_addr + sizeof (buf[0]) * i, 
                    (uint8_t *) & buf[i], sizeof (buf[0]), cpu)) {
                buf[0] = 0;
                return 0;
            }
        }
        buf[nRead] = 0;
        return i;
    }
    
    bool LengthSpecifiedString::getBytesFromHost(void * cpu, const uint8_t * pDataInHost, uint8_t outBuf[],
                int outBufLen, int &actualLen, int nBytesRead) {
        
        StringMetaData& rMetadata = reinterpret_cast<StringMetaData&>(this->getMetaData());
        int charSize = rMetadata.getCharSize();
        assert(charSize == 1 || charSize == 2);

//        IEnv &env = rMetadata.getEnv();
        
        // needs clarify here, is strLength in bytes or the number of characters?
        // if charSize is wide, strLength will be different!
        // ANS: Assume safe side, strLength is the number of chars.
        // At most, this assumption will make the system allocate twice the required size
        uint32_t strLength = 0;
        if (nBytesRead) {
            strLength = nBytesRead;
            
        } else {
            uint8_t * tmp = reinterpret_cast<uint8_t*>(&strLength);
            for (int i=0; i<rMetadata.getLengthOffsetSize(); ++i) {
                *(tmp+i) = *(pDataInHost - rMetadata.getLengthOffset() + i);
            }
        }
        
        // also check space for null character!
        if (outBuf == NULL || outBufLen < (strLength+1)*charSize) {
            actualLen = (strLength+1)*charSize; // add space for zero character
            return false;
        }

        int tlen = 0;
        if (charSize == 1) {
            tlen = charSize*(this->readNAsciiFromHost(cpu, (char*) outBuf, strLength, pDataInHost)+1);
        } else if (charSize == 2) {
            tlen = charSize*(this->readNWideFromHost(cpu, (uint16_t*) outBuf, strLength, pDataInHost)+1);
        }

        actualLen = tlen;
        return true;
        
    }

    bool LengthSpecifiedString::getBytes(void * cpu, uint64_t addr, uint8_t outBuf[], 
                int outBufLen, int &actualLen, int nBytesRead) {
        
        StringMetaData& rMetadata = reinterpret_cast<StringMetaData&>(this->getMetaData());
        int charSize = rMetadata.getCharSize();
        assert(charSize == 1 || charSize == 2);

        IEnv &env = rMetadata.getEnv();
        
        // needs clarify here, is strLength in bytes or the number of characters?
        // if charSize is wide, strLength will be different!
        // ANS: Assume safe side, strLength is the number of chars.
        // At most, this assumption will make the system allocate twice the required size
        uint32_t strLength = 0;
        if (nBytesRead) {
            strLength = nBytesRead;
            
        } else {
            if (IEnv::S_OK != env.readEnv(addr - rMetadata.getLengthOffset(),
                    (uint8_t*) & strLength, rMetadata.getLengthOffsetSize(), cpu)) {
                actualLen = strLength + charSize; // add space for zero character
                return false;
            }
            
        }
        
        // also check space for null character!
        if (outBuf == NULL || outBufLen < (strLength+1)*charSize) {
            actualLen = (strLength+1)*charSize; // add space for zero character
            return false;
        }

        int tlen = 0;
        if (charSize == 1) {
            tlen = charSize*(this->readNAsciiFromGuest(cpu, (char*) outBuf, strLength, addr)+1);
        } else if (charSize == 2) {
            tlen = charSize*(this->readNWideFromGuest(cpu, (uint16_t*) outBuf, strLength, addr)+1);
        }

        actualLen = tlen;
        return true;
    }
}