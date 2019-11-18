/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   wintypessimpletest.cpp
 * Author: darryl
 *
 * Created on November 3, 2018, 1:19 PM
 */

#include <stdlib.h>
#include <iostream>
#include <iomanip>

#include "TestInterface.h"
#include "IWinTypes.h"
#include "DummyEnv.h"

/*
 * Simple C++ Test Suite
 */

namespace Tests {
	namespace LiteralType {
		#define CURRDIR "../res"
		#define TESTNAME "LiteralTypeTest"
		#define TESTSUITENAME TESTNAME

		using namespace WinApiLib;
		DummyEnv gEnv;

		void testSimpleLiteralType_int32_getSucess() {
			const char * METHOD_NAME = "testSimpleLiteralType_int32_getSucess";
			
			IWinTypeData * dataInt32 = NULL;
			IWinTypes * winTypes = createWinTypes(gEnv, CURRDIR"/literaltypes.csv");
			if (winTypes == NULL) {
				std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTNAME ") "
						"message=expect winTypes not null got null" << std::endl;
				releaseWinTypeData(dataInt32);
				releaseWinTypes(winTypes);
				return;
			}
			
		//    winTypes->init();
			
			dataInt32 = winTypes->findData("int32");
			if (dataInt32 == NULL) {
				std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTNAME ") "
						"message=expect dataInt32 not null got null" << std::endl;
				releaseWinTypeData(dataInt32);
				releaseWinTypes(winTypes);
				return;
			}
			int outlen = 0;
			/**
			 * void * cpu, uint64_t addr, uint8_t outBuf[], 
						int outBufLen, int &actualLen, int nBytesRead = 0
			 */
			uint64_t data = 0;
			bool res = dataInt32->getBytes(NULL, 0, (uint8_t*)(&data), sizeof(data), outlen);
			if (!res) {
				std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTNAME ") "
						"message=expect ptr not null got null" << std::endl;
				releaseWinTypeData(dataInt32);
				releaseWinTypes(winTypes);
				return;
			}
			
			if (outlen != 4) {
				std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTNAME ") "
						"message=expect outlen " << 4 << " got " << outlen << std::endl;
				releaseWinTypeData(dataInt32);
				releaseWinTypes(winTypes);
				return;
			}
			
			// 0x0a,0x30,0x31,0x32
			const uint32_t * pRef = reinterpret_cast<const uint32_t*> (&data);
			if (*pRef != 0x3231300a) {
				std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTNAME ") "
						"message=expect *pRef " << std::hex << 0x33323130 << " got " << std::hex << *pRef << std::endl;
				releaseWinTypeData(dataInt32);
				releaseWinTypes(winTypes);
				return;
			}
			
		}

		void testSimpleLiteralType_uint64_getSucess() {
			const char * METHOD_NAME = "testSimpleLiteralType_uint64_getSucess";
			
			IWinTypeData * dataUint64 = NULL;
			IWinTypes * winTypes = createWinTypes(gEnv, CURRDIR"/literaltypes.csv");
			if (winTypes == NULL) {
				std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTNAME ") "
						"message=expect winTypes not null got null" << std::endl;
				releaseWinTypeData(dataUint64);
				releaseWinTypes(winTypes);
				return;
			}
			
		//    winTypes->init();
			
			dataUint64 = winTypes->findData("uint64");
			if (dataUint64 == NULL) {
				std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTNAME ") "
						"message=expect dataInt32 not null got null" << std::endl;
				releaseWinTypeData(dataUint64);
				releaseWinTypes(winTypes);
				return;
			}
			int outlen = 0;
			uint64_t data = 0;
			bool res = dataUint64->getBytes(NULL, 0, (uint8_t*)(&data), sizeof(data), outlen);
			if (!res) {
				std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTNAME ") "
						"message=expect ptr not null got null" << std::endl;
				releaseWinTypeData(dataUint64);
				releaseWinTypes(winTypes);
				return;
			}
			
			if (outlen != 8) {
				std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTNAME ") "
						"message=expect outlen " << 4 << " got " << outlen << std::endl;
				releaseWinTypeData(dataUint64);
				releaseWinTypes(winTypes);
				return;
			}
			
			// 0x0a,0x30,0x31,0x32,0x33,0x34,0x35,0x36
			const uint64_t * pRef = reinterpret_cast<const uint64_t*> (&data);
			uint64_t expected = 0x363534333231300aL;
			if (*pRef != expected) {
				std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTNAME ") "
						"message=expect *pRef 0x" << std::hex << expected << " got 0x" << std::hex << *pRef << std::endl;
				releaseWinTypeData(dataUint64);
				releaseWinTypes(winTypes);
				return;
			}
			
		}

		void testSimpleLiteralType_fallback_getUInt32() {
			const char * METHOD_NAME = "testSimpleLiteralType_fallback_getUInt32";
			
			IWinTypeData * dataUint64 = NULL;
			IWinTypes * winTypes = createWinTypes(gEnv, CURRDIR"/literaltypes.csv");
			if (winTypes == NULL) {
				std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTNAME ") "
						"message=expect winTypes not null got null" << std::endl;
				releaseWinTypeData(dataUint64);
				releaseWinTypes(winTypes);
				return;
			}
			
		//    winTypes->init();
			
			dataUint64 = winTypes->findData("KKK");
			if (dataUint64 == NULL) {
				std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTNAME ") "
						"message=expect dataInt32 not null got null" << std::endl;
				releaseWinTypeData(dataUint64);
				releaseWinTypes(winTypes);
				return;
			}
			int outlen = 0;
			uint64_t data = 0;
			bool res = dataUint64->getBytes(NULL, 0, (uint8_t*)(&data), sizeof(data), outlen);
			if (!res) {
				std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTNAME ") "
						"message=expect ptr not null got null" << std::endl;
				releaseWinTypeData(dataUint64);
				releaseWinTypes(winTypes);
				return;
			}
			
			if (outlen != 4) {
				std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTNAME ") "
						"message=expect outlen " << 4 << " got " << outlen << std::endl;
				releaseWinTypeData(dataUint64);
				releaseWinTypes(winTypes);
				return;
			}
			
			// 0x0a,0x30,0x31,0x32,0x33,0x34,0x35,0x36
			const uint32_t * pRef = reinterpret_cast<const uint32_t*> (&data);
			uint32_t expected = 0x3231300aL;
			if (*pRef != expected) {
				std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTNAME ") "
						"message=expect *pRef 0x" << std::hex << expected << " got 0x" << std::hex << *pRef << std::endl;
				releaseWinTypeData(dataUint64);
				releaseWinTypes(winTypes);
				return;
			}
			
		}

		void testSimpleLiteralType_int32_ExpectFailedGetSize() {
			const char * METHOD_NAME = "testSimpleLiteralType_int32_ExpectFailedGetSize";
			
			IWinTypeData * dataUint64 = NULL;
			IWinTypes * winTypes = createWinTypes(gEnv, CURRDIR"/literaltypes.csv");
			if (winTypes == NULL) {
				std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTNAME ") "
						"message=expect winTypes not null got null" << std::endl;
				releaseWinTypeData(dataUint64);
				releaseWinTypes(winTypes);
				return;
			}
			
		//    winTypes->init();
			
			dataUint64 = winTypes->findData("int32");
			if (dataUint64 == NULL) {
				std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTNAME ") "
						"message=expect dataInt32 not null got null" << std::endl;
				releaseWinTypeData(dataUint64);
				releaseWinTypes(winTypes);
				return;
			}
			int outlen = 0;
			bool res = dataUint64->getBytes(NULL, 0, NULL, 0, outlen);
			if (res) {
				std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTNAME ") "
						"message=expect ptr not null got null" << std::endl;
				releaseWinTypeData(dataUint64);
				releaseWinTypes(winTypes);
				return;
			}
			
			if (outlen != 4) {
				std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTNAME ") "
						"message=expect outlen " << 4 << " got " << outlen << std::endl;
				releaseWinTypeData(dataUint64);
				releaseWinTypes(winTypes);
				return;
			}
			
		}

		void testUint64OnHostExpectSuccess() {
			const char * METHOD_NAME = "testUint64OnHostExpectSuccess";
			
			IWinTypeData * dataUint64 = NULL;
			IWinTypes * winTypes = createWinTypes(gEnv, CURRDIR"/literaltypes.csv");
			if (winTypes == NULL) {
				std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTNAME ") "
						"message=expect winTypes not null got null" << std::endl;
				releaseWinTypeData(dataUint64);
				releaseWinTypes(winTypes);
				return;
			}
			
			dataUint64 = winTypes->findData("uint64");
			if (dataUint64 == NULL) {
				std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTNAME ") "
						"message=expect dataInt32 not null got null" << std::endl;
				releaseWinTypeData(dataUint64);
				releaseWinTypes(winTypes);
				return;
			}
			int outlen = 0;
			uint64_t data = 0;
			uint64_t expected = 0x363534333231300aL;
			
		//    bool res = dataUint64->getBytes(NULL, 0, (uint8_t*)(&data), sizeof(data), outlen);
			bool res = dataUint64->getBytesFromHost(NULL, (uint8_t*)(&expected), (uint8_t*)(&data), sizeof(data), outlen);
			if (!res) {
				std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTNAME ") "
						"message=expect ptr not null got null" << std::endl;
				releaseWinTypeData(dataUint64);
				releaseWinTypes(winTypes);
				return;
			}
			
			if (outlen != sizeof(expected)) {
				std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTNAME ") "
						"message=expect outlen " << 4 << " got " << outlen << std::endl;
				releaseWinTypeData(dataUint64);
				releaseWinTypes(winTypes);
				return;
			}
			
			// 0x0a,0x30,0x31,0x32,0x33,0x34,0x35,0x36
			const uint64_t * pRef = reinterpret_cast<const uint64_t*> (&data);
			if (*pRef != expected) {
				std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTNAME ") "
						"message=expect *pRef 0x" << std::hex << expected << " got 0x" << std::hex << *pRef << std::endl;
				releaseWinTypeData(dataUint64);
				releaseWinTypes(winTypes);
				return;
			}
		}

		#define T(X) RUNFUNC(X,TESTSUITENAME)

		void runTest_LiteralTypeTest() {
			std::cout << "%SUITE_STARTING% "TESTNAME << std::endl;
			std::cout << "%SUITE_STARTED%" << std::endl;

			T(testSimpleLiteralType_int32_getSucess);
			T(testSimpleLiteralType_uint64_getSucess);
			T(testSimpleLiteralType_fallback_getUInt32);
			T(testSimpleLiteralType_int32_ExpectFailedGetSize);
			T(testUint64OnHostExpectSuccess);
			
			std::cout << "%SUITE_FINISHED% time=0" << std::endl;
		}
	}
}

void runTest_LiteralTypeTest() {
	Tests::LiteralType::runTest_LiteralTypeTest();
}

