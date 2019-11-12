/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   StringData.h
 * Author: darryl
 *
 * Created on November 3, 2018, 2:59 PM
 */

#ifndef STRINGDATA_H
#define STRINGDATA_H

#include "IWinTypes.h"
#include "IWinTypeMetaData.h"
#include "StringMetaData.h"
#include "CommonData.h"

namespace WinApiLib {
        
#define MAX_STRING_LENGTH 512
    class ZeroTerminatedString : public CommonData {
    public:
        ZeroTerminatedString(StringMetaData &metadata);
        ~ZeroTerminatedString();
        bool getBytes(void * cpu, uint64_t addr, uint8_t outBuf[], 
                int outBufLen, int &actualLen, int nBytesRead = 0);
        bool getBytesFromHost(void * cpu, const uint8_t * pDataInHost, uint8_t outBuf[],
                int outBufLen, int &actualLen, int nBytesRead = 0);
        
    private:
        int readWideFromGuest(void *cpu, uint16_t *buf, int maxlen, uint64_t guest_addr);
        int readAsciiFromGuest(void *cpu, char *buf, int maxlen, uint64_t guest_addr);
        int readWideFromHost(void *cpu, uint16_t *buf, int maxlen, const uint8_t * hostAddr);
        int readAsciiFromHost(void *cpu, char *buf, int maxlen, const uint8_t * hostAddr);
    };
    
    class LengthSpecifiedString : public CommonData {
    public:
        LengthSpecifiedString(StringMetaData &metadata);
        ~LengthSpecifiedString();
        bool getBytes(void * cpu, uint64_t addr, uint8_t outBuf[], 
                int outBufLen, int &actualLen, int nBytesRead = 0);
        bool getBytesFromHost(void * cpu, const uint8_t * pDataInHost, uint8_t outBuf[],
                int outBufLen, int &actualLen, int nBytesRead = 0);
        
    private:
        int readNWideFromGuest(void *cpu, uint16_t *buf, int nRead, uint64_t guest_addr);
        int readNAsciiFromGuest(void *cpu, char *buf, int nRead, uint64_t guest_addr);
        int readNWideFromHost(void *cpu, uint16_t *buf, int nRead, const uint8_t * hostAddr);
        int readNAsciiFromHost(void *cpu, char *buf, int nRead, const uint8_t * hostAddr);
        
    };
}

#endif /* STRINGDATA_H */

