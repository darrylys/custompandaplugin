/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   WinApisTest.cpp
 * Author: darryl
 *
 * Created on November 17, 2018, 8:14 AM
 */

#include <stdlib.h>
#include <iostream>
#include <iomanip>
#include <stdint.h>
#include <string.h>

#include "IEnv.h"
#include "IWinApis.h"
#include "IWinTypes.h"
#include "TestInterface.h"

namespace Tests {
	namespace WinApis {
#define CURRDIR "../res"
#define TESTSUITENAME "WinApisTest"
#define DATATYPECSV "/apifndb.csv"
#define ABSDCSV CURRDIR DATATYPECSV

/*
 * Simple C++ Test Suite
 */

using namespace WinApiLib;

class NopEnv : public IEnv {
public:
    NopEnv(){}
    ~NopEnv(){}
    int readEnv(uint64_t addr, uint8_t * buf, int len, void * extra) {}
    int writeEnv(uint64_t addr, uint8_t * buf, int len, void * extra) {}
};

NopEnv gEnv;

class Handler {
public:
    Handler(IEnv& env, const char * testfile) {
        this->ptr = createWinApiParser(env, testfile);
    }
    
    ~Handler() {
        releaseWinApiParser(this->ptr);
    }
    
    IWinApis* get() {
        return this->ptr;
    }
    
private:
    IWinApis* ptr;
};

bool cmpFuncParamDesc(const char * METHOD_NAME, const FUNC_PARAM_DESC& observed, const FUNC_PARAM_DESC& expected) {
    if (strcmp(observed.name, expected.name) != 0) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect name " << expected.name << ", observed " << observed.name << std::endl;
        return false;
    }
    
    if (strcmp(observed.type, expected.type) != 0) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect type " << expected.type << ", observed " << observed.type << std::endl;
        return false;
    }
    
    if (expected.usage != observed.usage) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect usage " << expected.usage << ", observed " << observed.usage << std::endl;
        return false;
    }
    
    return true;
}

bool cmpFuncDesc(const char * METHOD_NAME, const FUNC_DESC& observed, const FUNC_DESC& expected) {
    if (strcasecmp(expected.dllName, observed.dllName) != 0) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect dllname " << expected.dllName << ", observed " << observed.dllName << std::endl;
        return false;
    }
    
    if (strcasecmp(expected.fnCallConvention, observed.fnCallConvention) != 0) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect call convention " << expected.fnCallConvention << ", observed " << observed.fnCallConvention << std::endl;
        return false;
    }
    
    if (strcasecmp(expected.fnReturnType, observed.fnReturnType) != 0) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect fnReturnType " << expected.fnReturnType << ", observed " << observed.fnReturnType << std::endl;
        return false;
    }
    
    if (strcmp(expected.fnName, observed.fnName) != 0) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect fnName " << expected.fnName << ", observed " << observed.fnName << std::endl;
        return false;
    }
    
    if (expected.fnOrd != observed.fnOrd) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect fnOrd " << std::dec << expected.fnOrd << ", observed " << std::dec << observed.fnOrd << std::endl;
        return false;
    }
    
    if (expected.fnRva != observed.fnRva) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect fnRva " << std::hex << expected.fnRva << ", observed " << std::hex << observed.fnRva << std::endl;
        return false;
    }
    
    if (expected.fnParam.size() != observed.fnParam.size()) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect param total: " << std::dec << expected.fnParam.size() << 
                ", observed " << std::dec << observed.fnParam.size() << std::endl;
        return false;
    }
    
    int sz = expected.fnParam.size();
    bool res = true;
    for (int i=0; res && i<sz; ++i) {
        res = res && cmpFuncParamDesc(METHOD_NAME, observed.fnParam[i], expected.fnParam[i]);
    }
    
    return res;
}

void testGetNtDeleteFileShouldSuccess() {
    const char * METHOD_NAME = "testGetNtDeleteFileShouldSuccess";
    std::cout << "WinApisTest " << METHOD_NAME << std::endl;
    
    Handler handler(gEnv, ABSDCSV);
    if (handler.get() == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect winTypes not null got null" << std::endl;
        return;
    }
    std::cout << "handler get" << std::endl;
    
    const char * expectedDll = "ntdll.dll";
    uint64_t ntdllBaseAddr = 0x100000;
    uint32_t expectedFnRva = 0x45808;
    
    IWinApis* ptr = handler.get();
    
    FUNC_DESC desc;
    bool findRes = ptr->findFunc(expectedDll, ntdllBaseAddr, ntdllBaseAddr + expectedFnRva, desc);
    if (!findRes) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect findFunc(0, 0x45808) return true, returns false" << std::endl;
        return;
    }
    
    std::cout << "findFunc passed" << std::endl;
    
    // should get:
    // ntdll.dll,0x45808,280,NTSTATUS,WINAPI,NtDeleteFile,in,OBJECT_ATTRIBUTES*,ObjectAttributes
    FUNC_DESC expectedFn;
    expectedFn.dllName = "ntdll.dll";
    expectedFn.fnCallConvention = "WINAPI";
    expectedFn.fnName = "NtDeleteFile";
    expectedFn.fnOrd = 280;
    expectedFn.fnReturnType = "NTSTATUS";
    expectedFn.fnRva = 0x45808;
    
    FUNC_PARAM_DESC expectedFnParam;
    expectedFnParam.name = "ObjectAttributes";
    expectedFnParam.type = "OBJECT_ATTRIBUTES*";
    expectedFnParam.usage = IN;
    
    expectedFn.fnParam.push_back(expectedFnParam);
    
    cmpFuncDesc(METHOD_NAME, desc, expectedFn);
}

void testGetNtDeleteFileDllCaseInsensitiveShouldSuccess() {
    const char * METHOD_NAME = "testGetNtDeleteFileDllCaseInsensitiveShouldSuccess";
    std::cout << "WinApisTest " << METHOD_NAME << std::endl;
    
    Handler handler(gEnv, ABSDCSV);
    if (handler.get() == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect winTypes not null got null" << std::endl;
        return;
    }
    std::cout << "handler get" << std::endl;
    
    const char * expectedDll = "NTDLL.DLL";
    uint64_t ntdllBaseAddr = 0x100000;
    uint32_t expectedFnRva = 0x45808;
    
    IWinApis* ptr = handler.get();
    
    FUNC_DESC desc;
    bool findRes = ptr->findFunc(expectedDll, ntdllBaseAddr, ntdllBaseAddr + expectedFnRva, desc);
    if (!findRes) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect findFunc(0, 0x45808) return true, returns false" << std::endl;
        return;
    }
    
    std::cout << "findFunc passed" << std::endl;
    
    // should get:
    // ntdll.dll,0x45808,280,NTSTATUS,WINAPI,NtDeleteFile,in,OBJECT_ATTRIBUTES*,ObjectAttributes
    FUNC_DESC expectedFn;
    expectedFn.dllName = "ntdll.dll";
    expectedFn.fnCallConvention = "WINAPI";
    expectedFn.fnName = "NtDeleteFile";
    expectedFn.fnOrd = 280;
    expectedFn.fnReturnType = "NTSTATUS";
    expectedFn.fnRva = 0x45808;
    
    FUNC_PARAM_DESC expectedFnParam;
    expectedFnParam.name = "ObjectAttributes";
    expectedFnParam.type = "OBJECT_ATTRIBUTES*";
    expectedFnParam.usage = IN;
    
    expectedFn.fnParam.push_back(expectedFnParam);
    
    cmpFuncDesc(METHOD_NAME, desc, expectedFn);
}

void testGetVersionNoParamExpectSuccess() {
    const char * METHOD_NAME = "testGetVersionNoParamExpectSuccess";
    std::cout << "WinApisTest " << METHOD_NAME << std::endl;
    
    Handler handler(gEnv, ABSDCSV);
    if (handler.get() == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect winTypes not null got null" << std::endl;
        return;
    }
    
    const char * expectedDll = "kernel32.dll";
    uint64_t ntdllBaseAddr = 0x200000;
    uint32_t expectedFnRva = 0x4154e;
    
    IWinApis* ptr = handler.get();
    
    FUNC_DESC desc;
    bool findRes = ptr->findFunc(expectedDll, ntdllBaseAddr, ntdllBaseAddr + expectedFnRva, desc);
    if (!findRes) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect findFunc(0, 0x45808) return true, returns false" << std::endl;
        return;
    }
    
    // should get:
    // kernel32.dll,0x4154e,675,DWORD,WINAPI,GetVersion
    
    FUNC_DESC expectedFn;
    expectedFn.dllName = "kernel32.dll";
    expectedFn.fnCallConvention = "WINAPI";
    expectedFn.fnName = "GetVersion";
    expectedFn.fnOrd = 675;
    expectedFn.fnReturnType = "DWORD";
    expectedFn.fnRva = 0x4154e;
    
    cmpFuncDesc(METHOD_NAME, desc, expectedFn);
}

void testGetNtOpenThreadExpectSuccess() {
    const char * METHOD_NAME = "testGetNtOpenThreadExpectSuccess";
    std::cout << "WinApisTest " << METHOD_NAME << std::endl;
    
    Handler handler(gEnv, ABSDCSV);
    if (handler.get() == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect winTypes not null got null" << std::endl;
        return;
    }
    
    const char * expectedDll = "ntdll.dll";
    uint64_t ntdllBaseAddr = 0x100000;
    uint32_t expectedFnRva = 0x45e08;
    
    IWinApis* ptr = handler.get();
    
    FUNC_DESC desc;
    bool findRes = ptr->findFunc(expectedDll, ntdllBaseAddr, ntdllBaseAddr + expectedFnRva, desc);
    if (!findRes) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect findFunc(0, 0x45808) return true, returns false" << std::endl;
        return;
    }
    
    // should get:
    // ntdll.dll,0x45e08,377,NTSTATUS,WINAPI,NtOpenThread,out,HANDLE*,ThreadHandle,
    // in,ACCESS_MASK,DesiredAccess,in,OBJECT_ATTRIBUTES*,ObjectAttributes,in,CLIENT_ID*,ClientId
    
    FUNC_DESC expectedFn;
    expectedFn.dllName = "ntdll.dll";
    expectedFn.fnCallConvention = "WINAPI";
    expectedFn.fnName = "NtOpenThread";
    expectedFn.fnOrd = 377;
    expectedFn.fnReturnType = "NTSTATUS";
    expectedFn.fnRva = 0x45e08;
    
    FUNC_PARAM_DESC expectedParam;
    
    expectedParam.name = "ThreadHandle";
    expectedParam.type = "HANDLE*";
    expectedParam.usage = OUT;
    expectedFn.fnParam.push_back(expectedParam);
    
    expectedParam.name = "DesiredAccess";
    expectedParam.type = "ACCESS_MASK";
    expectedParam.usage = IN;
    expectedFn.fnParam.push_back(expectedParam);
    
    expectedParam.name = "ObjectAttributes";
    expectedParam.type = "OBJECT_ATTRIBUTES*";
    expectedParam.usage = IN;
    expectedFn.fnParam.push_back(expectedParam);
    
    expectedParam.name = "ClientId";
    expectedParam.type = "CLIENT_ID*";
    expectedParam.usage = IN;
    expectedFn.fnParam.push_back(expectedParam);
    
    cmpFuncDesc(METHOD_NAME, desc, expectedFn);
}

void testUnknownFnShouldFail() {
    const char * METHOD_NAME = "testUnknownFnShouldFail";
    std::cout << "WinApisTest " << METHOD_NAME << std::endl;
    
    Handler handler(gEnv, ABSDCSV);
    if (handler.get() == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect winTypes not null got null" << std::endl;
        return;
    }
    
    const char * expectedDll = "ntdll.dll";
    uint64_t ntdllBaseAddr = 0x100000;
    
    IWinApis* ptr = handler.get();
    
    FUNC_DESC desc;
    bool findRes = ptr->findFunc(expectedDll, ntdllBaseAddr, ntdllBaseAddr + 0x12345, desc);
    if (findRes) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect findFunc(" << std::hex << ntdllBaseAddr << ", 0x12345) return false, returns true" << std::endl;
        return;
    }
    
}

void testSameFuncFromKernel32DllExpectSuccess() {
    const char * METHOD_NAME = "testSameFuncFromKernel32DllExpectSuccess";
    std::cout << "WinApisTest " << METHOD_NAME << std::endl;
    
    Handler handler(gEnv, ABSDCSV);
    if (handler.get() == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect winTypes not null got null" << std::endl;
        return;
    }
    
    const char * expectedDll = "kernel32.dll";
    uint64_t ntdllBaseAddr = 0x100000;
    uint32_t expectedFnRva = 0x67890;
    
    IWinApis* ptr = handler.get();
    
    FUNC_DESC desc;
    bool findRes = ptr->findFunc(expectedDll, ntdllBaseAddr, ntdllBaseAddr + expectedFnRva, desc);
    if (!findRes) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect findFunc(0, 0x45808) return true, returns false" << std::endl;
        return;
    }
    
    // should get:
    // kernel32.dll,0x67890,1240,DWORD,WINAPI,SameFunc,in,HANDLE*,pHandle,in,INT,Length
    
    FUNC_DESC expectedFn;
    expectedFn.dllName = expectedDll;
    expectedFn.fnCallConvention = "WINAPI";
    expectedFn.fnName = "SameFunc";
    expectedFn.fnOrd = 1240;
    expectedFn.fnReturnType = "DWORD";
    expectedFn.fnRva = expectedFnRva;
    
    FUNC_PARAM_DESC expectedParam;
    
    expectedParam.name = "pHandle";
    expectedParam.type = "HANDLE*";
    expectedParam.usage = IN;
    expectedFn.fnParam.push_back(expectedParam);
    
    expectedParam.name = "Length";
    expectedParam.type = "INT";
    expectedParam.usage = IN;
    expectedFn.fnParam.push_back(expectedParam);
    
    cmpFuncDesc(METHOD_NAME, desc, expectedFn);
}

void testSameFuncFromAdvapi32DllExpectSuccess() {
    const char * METHOD_NAME = "testSameFuncFromAdvapi32DllExpectSuccess";
    std::cout << "WinApisTest " << METHOD_NAME << std::endl;
    
    Handler handler(gEnv, ABSDCSV);
    if (handler.get() == NULL) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect winTypes not null got null" << std::endl;
        return;
    }
    
    const char * expectedDll = "advapi32.dll";
    uint64_t ntdllBaseAddr = 0x100000;
    uint32_t expectedFnRva = 0x12345;
    
    IWinApis* ptr = handler.get();
    
    FUNC_DESC desc;
    bool findRes = ptr->findFunc(expectedDll, ntdllBaseAddr, ntdllBaseAddr + expectedFnRva, desc);
    if (!findRes) {
        std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
                "message=expect findFunc(0, 0x45808) return true, returns false" << std::endl;
        return;
    }
    
    // should get:
    // advapi32.dll,0x12345,1000,DWORD,WINAPI,SameFunc,in,STR*,word
    
    FUNC_DESC expectedFn;
    expectedFn.dllName = expectedDll;
    expectedFn.fnCallConvention = "WINAPI";
    expectedFn.fnName = "SameFunc";
    expectedFn.fnOrd = 1000;
    expectedFn.fnReturnType = "DWORD";
    expectedFn.fnRva = expectedFnRva;
    
    FUNC_PARAM_DESC expectedParam;
    
    expectedParam.name = "word";
    expectedParam.type = "STR*";
    expectedParam.usage = IN;
    expectedFn.fnParam.push_back(expectedParam);
    
    cmpFuncDesc(METHOD_NAME, desc, expectedFn);
}

#define T(X) RUNFUNC(X,TESTSUITENAME)

void runTest_WinApisTest() {
    std::cout << "%SUITE_STARTING% WinApisTest" << std::endl;
    std::cout << "%SUITE_STARTED%" << std::endl;

    T(testGetNtDeleteFileShouldSuccess);
    T(testGetNtOpenThreadExpectSuccess);
    T(testGetVersionNoParamExpectSuccess);
    T(testUnknownFnShouldFail);
    T(testGetNtDeleteFileDllCaseInsensitiveShouldSuccess);
    T(testSameFuncFromAdvapi32DllExpectSuccess);
    T(testSameFuncFromKernel32DllExpectSuccess);
    
    std::cout << "%SUITE_FINISHED% time=0" << std::endl;
}
		
	}
}

void runTest_WinApisTest() {
	Tests::WinApis::runTest_WinApisTest();
}
