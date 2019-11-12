/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "StringData.h"
#include <assert.h>

#include <vector>

namespace WinApiLib {

    ZeroTerminatedString::ZeroTerminatedString(StringMetaData &metadata)
    : CommonData(metadata) {

    }

    ZeroTerminatedString::~ZeroTerminatedString() {
    }
    
    int ZeroTerminatedString::readWideFromHost(void *cpu, uint16_t *buf, int maxlen, const uint8_t * hostAddr) {
        
        buf[0] = 0;
        unsigned i = 0;
        
        for (i = 0; i < maxlen; i++) {
            
            uint8_t* tmp = reinterpret_cast<uint8_t*>(buf+i);
            tmp[0] = *(hostAddr + sizeof(buf[0])*i);
            tmp[1] = *(hostAddr + sizeof(buf[0])*i + 1);
            
            if (buf[i] == 0) {
                break;
            }
        }
        buf[maxlen - 1] = 0;
        return i;
        
    }
    
    int ZeroTerminatedString::readAsciiFromHost(void *cpu, char *buf, int maxlen, const uint8_t * hostAddr) {
        
        buf[0] = 0;
        unsigned i = 0;
        
        for (i = 0; i < maxlen; i++) {
            
            buf[i] = (char)(*(hostAddr + i));
            if (buf[i] == 0) {
                break;
            }
        }
        buf[maxlen - 1] = 0;
        return i;
        
    }
    
    int ZeroTerminatedString::readAsciiFromGuest(void* cpu, char* buf, 
            int maxlen, uint64_t guest_addr) {
        
        buf[0] = 0;
        unsigned i = 0;
        
        StringMetaData& rMetadata = reinterpret_cast<StringMetaData&>(this->getMetaData());
        IEnv &env = rMetadata.getEnv();
        
        for (i = 0; i < maxlen; i++) {
            if (IEnv::S_OK != env.readEnv(guest_addr + sizeof (buf[0]) * i, 
                    (uint8_t *) & buf[i], sizeof (buf[0]), cpu)) {
                buf[0] = 0;
                return 0;
            }
            if (buf[i] == 0) {
                break;
            }
        }
        buf[maxlen - 1] = 0;
        return i;
        
    }
    
    int ZeroTerminatedString::readWideFromGuest(void* cpu, uint16_t* buf, 
            int maxlen, uint64_t guest_addr) {
        
        buf[0] = 0;
        unsigned i = 0;
        
        StringMetaData& rMetadata = reinterpret_cast<StringMetaData&>(this->getMetaData());
        IEnv &env = rMetadata.getEnv();
        
        for (i = 0; i < maxlen; i++) {
            if (IEnv::S_OK != env.readEnv(guest_addr + sizeof (buf[0]) * i, 
                    (uint8_t *) & buf[i], sizeof (buf[0]), cpu)) {
                buf[0] = 0;
                return 0;
            }
            if (buf[i] == 0) {
                break;
            }
        }
        buf[maxlen - 1] = 0;
        return i;
        
    }
    
    bool ZeroTerminatedString::getBytesFromHost(void * cpu, const uint8_t * pDataInHost, uint8_t outBuf[],
                int outBufLen, int &actualLen, int nBytesRead) {
        
        StringMetaData& rMetadata = reinterpret_cast<StringMetaData&>(this->getMetaData());
        int charSize = rMetadata.getCharSize();
        assert(charSize == 1 || charSize == 2);

        int maxlen = MAX_STRING_LENGTH+1; // add room for zero character
        if (nBytesRead) {
            maxlen = nBytesRead;
        }
        
        // save space for last zero character
        std::vector<uint8_t> vBuf((maxlen) * charSize); // reserve buffer size for maxlen elements
        int tlen = 0;
        // tlen is added by 1 to give room for zero character at the end
        if (charSize == 1) {
            tlen = charSize * ( this->readAsciiFromHost(cpu, (char*) 
                    &vBuf[0], maxlen, pDataInHost) + 1 );
            
        } else if (charSize == 2) {
            tlen = charSize * ( this->readWideFromHost(cpu, (uint16_t*)
                    &vBuf[0], maxlen, pDataInHost) + 1 );
            
        }
        
        if (outBuf == NULL || outBufLen < tlen) {
            actualLen = tlen;
            return false;
        }

        for (int i=0; i<tlen; ++i) {
            outBuf[i] = vBuf[i];
        }
        actualLen = tlen;
        return true;
        
    }

    bool ZeroTerminatedString::getBytes(void * cpu, uint64_t addr, uint8_t outBuf[], 
                int outBufLen, int &actualLen, int nBytesRead) {

        StringMetaData& rMetadata = reinterpret_cast<StringMetaData&>(this->getMetaData());
        int charSize = rMetadata.getCharSize();
        assert(charSize == 1 || charSize == 2);

        int maxlen = MAX_STRING_LENGTH+1; // add room for zero character
        if (nBytesRead) {
            maxlen = nBytesRead;
        }
        
        // save space for last zero character
        std::vector<uint8_t> vBuf((maxlen) * charSize); // reserve buffer size for maxlen elements
        int tlen = 0;
        // tlen is added by 1 to give room for zero character at the end
        if (charSize == 1) {
            tlen = charSize * ( this->readAsciiFromGuest(cpu, (char*) 
                    &vBuf[0], maxlen, addr) + 1 );
            
        } else if (charSize == 2) {
            tlen = charSize * ( this->readWideFromGuest(cpu, (uint16_t*)
                    &vBuf[0], maxlen, addr) + 1 );
            
        }
        
        if (outBuf == NULL || outBufLen < tlen) {
            actualLen = tlen;
            return false;
        }

        for (int i=0; i<tlen; ++i) {
            outBuf[i] = vBuf[i];
        }
        actualLen = tlen;
        return true;
    }
}