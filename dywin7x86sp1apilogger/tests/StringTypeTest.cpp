/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include <stdlib.h>
#include <iostream>
#include <iomanip>

#include "TestInterface.h"
#include "IWinTypes.h"
#include "DummyEnv.h"

namespace Tests {
	namespace StringType {
#define CURRDIR "../res"
#define TESTSUITENAME "WinTypeStringTest"
#define DATATYPECSV "/stringtypes.csv"
#define ABSDCSV CURRDIR DATATYPECSV

using namespace WinApiLib;

DummyEnv gEnv;

void testStringPSTR() {
    const char * METHOD_NAME = "testStringPSTR";
    
    IWinTypeData * dataUint64 = NULL;
    IWinTypes * winTypes = createWinTypes(gEnv, ABSDCSV);
    if (winTypes == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect winTypes not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    //winTypes->init();
    
    dataUint64 = winTypes->findData("PSTR");
    if (dataUint64 == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect dataInt32 not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    int outlen = 0;
    uint8_t strBuf[128];
    bool res = dataUint64->getBytes(NULL, 0, strBuf, sizeof(strBuf), outlen);
    if (!res) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect ptr not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    const uint8_t expected[] = {
        0x0a,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x40,0x41,0x42,0x43,0
    };
    const int expectedLen = sizeof(expected);
    if (outlen != expectedLen) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect expectedLen " << expectedLen << " got " << outlen << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    for (int i=0; i<expectedLen; ++i) {
        if (expected[i] != strBuf[i]) {
            std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect at idx " << std::dec << i << " 0x" << 
                    std::hex << expected[i] << " got 0x" << std::hex << strBuf[i] << std::endl;
            break;
        }
    }
    
    releaseWinTypeData(dataUint64);
    releaseWinTypes(winTypes);
    return;
    
}
void testStringPSTRFromHost() {
    const char * METHOD_NAME = "testStringPSTRFromHost";
    
    IWinTypeData * dataUint64 = NULL;
    IWinTypes * winTypes = createWinTypes(gEnv, ABSDCSV);
    if (winTypes == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect winTypes not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    //winTypes->init();
    
    dataUint64 = winTypes->findData("PSTR");
    if (dataUint64 == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect dataInt32 not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    int outlen = 0;
    uint8_t strBuf[128];
    
    const uint8_t expected[] = {
        0x0a,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x40,0x41,0x42,0x43,0
    };
    
    //bool res = dataUint64->getBytes(NULL, 0, strBuf, sizeof(strBuf), outlen);
    bool res = dataUint64->getBytesFromHost(NULL, expected, strBuf, sizeof(strBuf), outlen);
    if (!res) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect ptr not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    
    const int expectedLen = sizeof(expected);
    if (outlen != expectedLen) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect expectedLen " << expectedLen << " got " << outlen << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    for (int i=0; i<expectedLen; ++i) {
        if (expected[i] != strBuf[i]) {
            std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect at idx " << std::dec << i << " 0x" << 
                    std::hex << expected[i] << " got 0x" << std::hex << strBuf[i] << std::endl;
            break;
        }
    }
    
    releaseWinTypeData(dataUint64);
    releaseWinTypes(winTypes);
    return;
    
}
void testStringPSTRNullBuffer_ExpectFailReturnLength() {
    const char * METHOD_NAME = "testStringPSTRNullBuffer_ExpectFailReturnLength";
    
    IWinTypeData * dataUint64 = NULL;
    IWinTypes * winTypes = createWinTypes(gEnv, ABSDCSV);
    if (winTypes == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect winTypes not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    //winTypes->init();
    
    dataUint64 = winTypes->findData("PSTR");
    if (dataUint64 == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect dataInt32 not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    int outlen = 0;
    bool res = dataUint64->getBytes(NULL, 0, NULL, 0, outlen);
    if (res) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect ptr not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    const uint8_t expected[] = {
        0x0a,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x40,0x41,0x42,0x43,0
    };
    const int expectedLen = sizeof(expected);
    if (outlen != expectedLen) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect expectedLen " << expectedLen << " got " << outlen << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    releaseWinTypeData(dataUint64);
    releaseWinTypes(winTypes);
    return;
    
}
void testStringPSTRFromHostNullBuffer_ExpectFailReturnLength() {
    const char * METHOD_NAME = "testStringPSTRFromHostNullBuffer_ExpectFailReturnLength";
    
    IWinTypeData * dataUint64 = NULL;
    IWinTypes * winTypes = createWinTypes(gEnv, ABSDCSV);
    if (winTypes == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect winTypes not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    //winTypes->init();
    
    dataUint64 = winTypes->findData("PSTR");
    if (dataUint64 == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect dataInt32 not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    int outlen = 0;
    const uint8_t expected[] = {
        0x0a,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x40,0x41,0x42,0x43,0
    };
    
    //bool res = dataUint64->getBytes(NULL, 0, NULL, 0, outlen);
    bool res = dataUint64->getBytesFromHost(NULL, expected, NULL, 0, outlen);
    if (res) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect ptr not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    const int expectedLen = sizeof(expected);
    if (outlen != expectedLen) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect expectedLen " << expectedLen << " got " << outlen << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    releaseWinTypeData(dataUint64);
    releaseWinTypes(winTypes);
    return;
    
}
void testStringPWSTR() {
    const char * METHOD_NAME = "testStringPWSTR";
    
    IWinTypeData * dataUint64 = NULL;
    IWinTypes * winTypes = createWinTypes(gEnv, ABSDCSV);
    if (winTypes == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect winTypes not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    //winTypes->init();
    
    dataUint64 = winTypes->findData("PWSTR");
    if (dataUint64 == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect dataInt32 not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    int outlen = 0;
    uint8_t strBuf[128];
    bool res = dataUint64->getBytes(NULL, 0, strBuf, sizeof(strBuf), outlen);
    if (!res) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect ptr not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    const uint16_t expected[] = {
        0x300a,0x3231,0x3433,0x3635,0x3837,0x4039,0x4241,0x0043,0
    };
    const int expectedLen = sizeof(expected);
    if (outlen != expectedLen) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect expectedLen " << expectedLen << " got " << outlen << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    const int el = sizeof(expected) / sizeof(expected[0]);
    const uint16_t * wptr = reinterpret_cast<const uint16_t*>(strBuf);
    for (int i=0; i<el; ++i) {
        if (expected[i] != wptr[i]) {
            std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect at idx " << std::dec << i << " 0x" << 
                    std::hex << expected[i] << " got 0x" << std::hex << wptr[i] << std::endl;
            break;
        }
    }
    
    releaseWinTypeData(dataUint64);
    releaseWinTypes(winTypes);
    return;
    
}
void testStringPWSTRFromHost() {
    const char * METHOD_NAME = "testStringPWSTRFromHost";
    
    IWinTypeData * dataUint64 = NULL;
    IWinTypes * winTypes = createWinTypes(gEnv, ABSDCSV);
    if (winTypes == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect winTypes not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    dataUint64 = winTypes->findData("PWSTR");
    if (dataUint64 == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect dataInt32 not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    int outlen = 0;
    uint8_t strBuf[128];
    const uint16_t expected[] = {
        0x300a,0x3231,0x3433,0x3635,0x3837,0x4039,0x4241,0x0043,0
    };
    //bool res = dataUint64->getBytes(NULL, 0, strBuf, sizeof(strBuf), outlen);
    bool res = dataUint64->getBytesFromHost(NULL, (uint8_t*)expected, strBuf, sizeof(strBuf), outlen);
    if (!res) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect ptr not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    const int expectedLen = sizeof(expected);
    if (outlen != expectedLen) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect expectedLen " << expectedLen << " got " << outlen << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    const int el = sizeof(expected) / sizeof(expected[0]);
    const uint16_t * wptr = reinterpret_cast<const uint16_t*>(strBuf);
    for (int i=0; i<el; ++i) {
        if (expected[i] != wptr[i]) {
            std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect at idx " << std::dec << i << " 0x" << 
                    std::hex << expected[i] << " got 0x" << std::hex << wptr[i] << std::endl;
            break;
        }
    }
    
    releaseWinTypeData(dataUint64);
    releaseWinTypes(winTypes);
    return;
    
}
void testStringPWSTRNullBuffer_ExpectFailReturnLength() {
    const char * METHOD_NAME = "testStringPWSTRNullBuffer_ExpectFailReturnLength";
    
    IWinTypeData * dataUint64 = NULL;
    IWinTypes * winTypes = createWinTypes(gEnv, ABSDCSV);
    if (winTypes == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect winTypes not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    //winTypes->init();
    
    dataUint64 = winTypes->findData("PWSTR");
    if (dataUint64 == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect dataInt32 not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    int outlen = 0;
    bool res = dataUint64->getBytes(NULL, 0, NULL, 0, outlen);
    if (res) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect ptr not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    const uint16_t expected[] = {
        0x300a,0x3231,0x3433,0x3635,0x3837,0x4039,0x4241,0x0043,0
    };
    const int expectedLen = sizeof(expected);
    if (outlen != expectedLen) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect expectedLen " << expectedLen << " got " << outlen << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    releaseWinTypeData(dataUint64);
    releaseWinTypes(winTypes);
    return;
    
}
void testStringPWSTRNullBufferFromHost_ExpectFailReturnLength() {
    const char * METHOD_NAME = "testStringPWSTRNullBufferFromHost_ExpectFailReturnLength";
    
    IWinTypeData * dataUint64 = NULL;
    IWinTypes * winTypes = createWinTypes(gEnv, ABSDCSV);
    if (winTypes == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect winTypes not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    //winTypes->init();
    
    dataUint64 = winTypes->findData("PWSTR");
    if (dataUint64 == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect dataInt32 not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    int outlen = 0;
    const uint16_t expected[] = {
        0x300a,0x3231,0x3433,0x3635,0x3837,0x4039,0x4241,0x0043,0
    };
    bool res = dataUint64->getBytesFromHost(NULL, (uint8_t*)expected, NULL, 0, outlen);
    if (res) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect ptr not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    const int expectedLen = sizeof(expected);
    if (outlen != expectedLen) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect expectedLen " << expectedLen << " got " << outlen << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    releaseWinTypeData(dataUint64);
    releaseWinTypes(winTypes);
    return;
    
}
void testStringBSTR() {
    const char * METHOD_NAME = "testStringBSTR";
    
    IWinTypeData * dataUint64 = NULL;
    IWinTypes * winTypes = createWinTypes(gEnv, ABSDCSV);
    if (winTypes == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect winTypes not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    //winTypes->init();
    
    dataUint64 = winTypes->findData("BSTR");
    if (dataUint64 == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect dataInt32 not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    int outlen = 0;
    uint8_t strBuf[128];
    bool res = dataUint64->getBytes(NULL, 1, strBuf, sizeof(strBuf), outlen);
    if (!res) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect ptr not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    const uint8_t expected[] = {
        0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x0
    };
    const int expectedLen = 11;
    if (outlen != expectedLen) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect expectedLen " << expectedLen << " got " << outlen << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    for (int i=0; i<expectedLen; ++i) {
        if (expected[i] != strBuf[i]) {
            std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect at idx " << std::dec << i << " 0x" << 
                    std::hex << expected[i] << " got 0x" << std::hex << strBuf[i] << std::endl;
            break;
        }
    }
    
    releaseWinTypeData(dataUint64);
    releaseWinTypes(winTypes);
    return;
    
}
void testStringBSTRFromHost() {
    const char * METHOD_NAME = "testStringBSTRFromHost";
    
    IWinTypeData * dataUint64 = NULL;
    IWinTypes * winTypes = createWinTypes(gEnv, ABSDCSV);
    if (winTypes == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect winTypes not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    dataUint64 = winTypes->findData("BSTR");
    if (dataUint64 == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect dataInt32 not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    int outlen = 0;
    uint8_t strBuf[128];
    const uint8_t data[] = {
        0x0a, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x40, 0x41, 0x42, 0x43, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    
    //bool res = dataUint64->getBytes(NULL, 1, strBuf, sizeof(strBuf), outlen);
    bool res = dataUint64->getBytesFromHost(NULL, data+1, strBuf, sizeof(strBuf), outlen); // source points at data[1]
    if (!res) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect ptr not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    const uint8_t expected[] = {
        0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x0
    };
    const int expectedLen = 11;
    if (outlen != expectedLen) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect expectedLen " << expectedLen << " got " << outlen << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    for (int i=0; i<expectedLen; ++i) {
        if (expected[i] != strBuf[i]) {
            std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect at idx " << std::dec << i << " 0x" << 
                    std::hex << expected[i] << " got 0x" << std::hex << strBuf[i] << std::endl;
            break;
        }
    }
    
    releaseWinTypeData(dataUint64);
    releaseWinTypes(winTypes);
    return;
    
}
void testStringBSTRNullBuffer_ExpectFailReturnLength() {
    const char * METHOD_NAME = "testStringBSTRNullBuffer_ExpectFailReturnLength";
    
    IWinTypeData * dataUint64 = NULL;
    IWinTypes * winTypes = createWinTypes(gEnv, ABSDCSV);
    if (winTypes == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect winTypes not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    //winTypes->init();
    
    dataUint64 = winTypes->findData("BSTR");
    if (dataUint64 == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect dataInt32 not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    int outlen = 0;
    bool res = dataUint64->getBytes(NULL, 1, NULL, 0, outlen);
    if (res) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect ptr not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    const uint8_t expected[] = {
        0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x0
    };
    const int expectedLen = 11;
    if (outlen != expectedLen) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect expectedLen " << expectedLen << " got " << outlen << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    releaseWinTypeData(dataUint64);
    releaseWinTypes(winTypes);
    return;
    
}
void testStringBSTRFromHostNullBuffer_ExpectFailReturnLength() {
    const char * METHOD_NAME = "testStringBSTRFromHostNullBuffer_ExpectFailReturnLength";
    
    IWinTypeData * dataUint64 = NULL;
    IWinTypes * winTypes = createWinTypes(gEnv, ABSDCSV);
    if (winTypes == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect winTypes not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    //winTypes->init();
    
    dataUint64 = winTypes->findData("BSTR");
    if (dataUint64 == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect dataInt32 not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    int outlen = 0;
    const uint8_t data[] = {
        0x0a, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x40, 0x41, 0x42, 0x43, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    bool res = dataUint64->getBytesFromHost(NULL, data+1, NULL, 0, outlen);
    if (res) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect ptr not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    const uint8_t expected[] = {
        0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x0
    };
    const int expectedLen = 11;
    if (outlen != expectedLen) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect expectedLen " << expectedLen << " got " << outlen << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    releaseWinTypeData(dataUint64);
    releaseWinTypes(winTypes);
    return;
    
}
void testStringBWSTR() {
    const char * METHOD_NAME = "testStringBWSTR";
    
    IWinTypeData * dataUint64 = NULL;
    IWinTypes * winTypes = createWinTypes(gEnv, ABSDCSV);
    if (winTypes == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect winTypes not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    //winTypes->init();
    
    dataUint64 = winTypes->findData("BWSTR");
    if (dataUint64 == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect dataInt32 not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    int outlen = 0;
    uint8_t strBuf[128];
    bool res = dataUint64->getBytes(NULL, 1, strBuf, sizeof(strBuf), outlen);
    if (!res) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect ptr not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    const uint16_t expected[] = {
        0x3130,0x3332,0x3534,0x3736,0x3938,0x4140,0x4342,0,0,0,0
    };
    const int expectedLen = 22;
    if (outlen != expectedLen) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect expectedLen " << expectedLen << " got " << outlen << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    const int el = 11;
    const uint16_t * wptr = reinterpret_cast<const uint16_t*>(strBuf);
    for (int i=0; i<el; ++i) {
        if (expected[i] != wptr[i]) {
            std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect at idx " << std::dec << i << " 0x" << 
                    std::hex << expected[i] << " got 0x" << std::hex << wptr[i] << std::endl;
            break;
        }
    }
    
    releaseWinTypeData(dataUint64);
    releaseWinTypes(winTypes);
    return;
    
}
void testStringBWSTRFromHost() {
    const char * METHOD_NAME = "testStringBWSTRFromHost";
    
    IWinTypeData * dataUint64 = NULL;
    IWinTypes * winTypes = createWinTypes(gEnv, ABSDCSV);
    if (winTypes == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect winTypes not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    dataUint64 = winTypes->findData("BWSTR");
    if (dataUint64 == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect dataInt32 not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    int outlen = 0;
    uint8_t strBuf[128];
    const uint8_t data[] = {
        0x0a, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x40, 0x41, 0x42, 0x43, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    //bool res = dataUint64->getBytes(NULL, 1, strBuf, sizeof(strBuf), outlen);
    bool res = dataUint64->getBytesFromHost(NULL, data+1, strBuf, sizeof(strBuf), outlen);
    if (!res) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect ptr not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    const uint16_t expected[] = {
        0x3130,0x3332,0x3534,0x3736,0x3938,0x4140,0x4342,0,0,0,0
    };
    const int expectedLen = 22;
    if (outlen != expectedLen) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect expectedLen " << expectedLen << " got " << outlen << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    const int el = 11;
    const uint16_t * wptr = reinterpret_cast<const uint16_t*>(strBuf);
    for (int i=0; i<el; ++i) {
        if (expected[i] != wptr[i]) {
            std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect at idx " << std::dec << i << " 0x" << 
                    std::hex << expected[i] << " got 0x" << std::hex << wptr[i] << std::endl;
            break;
        }
    }
    
    releaseWinTypeData(dataUint64);
    releaseWinTypes(winTypes);
    return;
    
}
void testStringBWSTRNullBuffer_ExpectReturnLength() {
    const char * METHOD_NAME = "testStringBWSTRNullBuffer_ExpectReturnLength";
    
    IWinTypeData * dataUint64 = NULL;
    IWinTypes * winTypes = createWinTypes(gEnv, ABSDCSV);
    if (winTypes == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect winTypes not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    //winTypes->init();
    
    dataUint64 = winTypes->findData("BWSTR");
    if (dataUint64 == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect dataInt32 not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    int outlen = 0;
    bool res = dataUint64->getBytes(NULL, 1, NULL, 0, outlen);
    if (res) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect ptr not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    const uint16_t expected[] = {
        0x3130,0x3332,0x3534,0x3736,0x3938,0x4140,0x4342,0,0,0,0
    };
    const int expectedLen = 22;
    if (outlen != expectedLen) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect expectedLen " << expectedLen << " got " << outlen << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    releaseWinTypeData(dataUint64);
    releaseWinTypes(winTypes);
    return;
    
}
void testStringBWSTRFromHostNullBuffer_ExpectReturnLength() {
    const char * METHOD_NAME = "testStringBWSTRFromHostNullBuffer_ExpectReturnLength";
    
    IWinTypeData * dataUint64 = NULL;
    IWinTypes * winTypes = createWinTypes(gEnv, ABSDCSV);
    if (winTypes == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect winTypes not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    //winTypes->init();
    
    dataUint64 = winTypes->findData("BWSTR");
    if (dataUint64 == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect dataInt32 not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    int outlen = 0;
    const uint8_t data[] = {
        0x0a, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x40, 0x41, 0x42, 0x43, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    //bool res = dataUint64->getBytes(NULL, 1, NULL, 0, outlen);
    bool res = dataUint64->getBytesFromHost(NULL, data+1, NULL, 0, outlen);
    if (res) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect ptr not null got null" << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    const uint16_t expected[] = {
        0x3130,0x3332,0x3534,0x3736,0x3938,0x4140,0x4342,0,0,0,0
    };
    const int expectedLen = 22;
    if (outlen != expectedLen) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect expectedLen " << expectedLen << " got " << outlen << std::endl;
        releaseWinTypeData(dataUint64);
        releaseWinTypes(winTypes);
        return;
    }
    
    releaseWinTypeData(dataUint64);
    releaseWinTypes(winTypes);
    return;
    
}

#define T(X) RUNFUNC(X,TESTSUITENAME)

void runTest_StringTypeTest() {
    std::cout << "%SUITE_STARTING% " TESTSUITENAME << std::endl;
    std::cout << "%SUITE_STARTED%" << std::endl;

    T(testStringPSTR);
    T(testStringPSTRNullBuffer_ExpectFailReturnLength);
    T(testStringPWSTR);
    T(testStringPWSTRNullBuffer_ExpectFailReturnLength);
    T(testStringBSTR);
    T(testStringBSTRNullBuffer_ExpectFailReturnLength);
    T(testStringBWSTR);
    T(testStringBWSTRNullBuffer_ExpectReturnLength);
    
    T(testStringPSTRFromHost);
    T(testStringPSTRFromHostNullBuffer_ExpectFailReturnLength);
    T(testStringPWSTRFromHost);
    T(testStringPWSTRNullBufferFromHost_ExpectFailReturnLength);
    T(testStringBSTRFromHost);
    T(testStringBSTRFromHostNullBuffer_ExpectFailReturnLength);
    T(testStringBWSTRFromHost);
    T(testStringBWSTRFromHostNullBuffer_ExpectReturnLength);
    
    std::cout << "%SUITE_FINISHED% time=0" << std::endl;
}		
	}
}

void runTest_StringTypeTest() {
	Tests::StringType::runTest_StringTypeTest();
}
