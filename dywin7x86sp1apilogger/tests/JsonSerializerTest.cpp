/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   JsonSerializerTest.cpp
 * Author: darryl
 *
 * Created on November 11, 2018, 1:59 PM
 */

#include <stdlib.h>
#include <iostream>

#include "TestInterface.h"
#include "JsonSerializer.h"
#include <string>
#include <sstream>
#include <stdint.h>
#include <iomanip>
#include <string.h>

namespace Tests {
	namespace JsonSerializer {
		#define TESTSUITENAME "JsonSerializerTest"

		using namespace WinApiLib::Json;

		void testJsonIntPrintDec() {
			const char * METHOD_NAME = "testJsonIntPrintDec";
			
			uint64_t expected = 0x55661122AABBCCDDLL;
			
			JsonInt jsonInt(expected);
			std::string observed = jsonInt.toJson();
			
			std::stringstream ss;
			ss << std::dec << expected;
			std::string strExpected = ss.str();
			
			if (strExpected != observed) {
				std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
						"message=expect " << strExpected << " observed " << observed << std::endl;
			}
		}

		void testJsonIntPrintHex() {
			
			const char * METHOD_NAME = "testJsonIntPrintHex";
			
			uint64_t expected = 0x55661122AABBCCDDLL;
			
			JsonIntHex jsonInt(expected);
			std::string observed = jsonInt.toJson();
			
			std::stringstream ss;
			ss << "\"0x" << std::hex << expected << "\"";
			std::string strExpected = ss.str();
			
			if (strExpected != observed) {
				std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
						"message=expect " << strExpected << " observed " << observed << std::endl;
			}
			
		}

		void testJsonStringAddQuotes() {
			
			const char * METHOD_NAME = "testJsonStringAddQuotes";
			
			std::string value("Test Json Add Quotes");
			
			JsonString jsonStr(value.c_str());
			std::string expected("\"");
			expected += value;
			expected += "\"";
			
			std::string observed = jsonStr.toJson();
			
			if (expected != observed) {
				std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
						"message=expect " << expected << " observed " << observed << std::endl;
			}
		}

		void testJsonStringWeirdCharsExpectHexIfNonPrintableAndDblQuotes() {
			
			const char * METHOD_NAME = "testJsonStringWeirdCharsExpectHexIfNonPrintableAndDblQuotes";
			
			char data[257];
			::memset(data, 0, sizeof(data));
			
			data[0] = (char)0x1;
			data[1] = (char)0x10;
			data[2] = (char)0x20;
			data[3] = (char)0x22;
			data[4] = (char)0x30;
			data[5] = (char)0x50;
			data[6] = (char)0x7e;
			data[7] = (char)0x7f;
			data[8] = (char)0x80;
			data[9] = (char)0xa0;
			data[10] = (char)0xff;
			data[11] = (char)0x0;
			
			std::string strData(data);
			
			JsonString jsonStr(strData.c_str());
			std::string expected("\"\\x01\\x10 \\x220P~\\x7f\\x80\\xa0\\xff\"");
			
			std::string observed = jsonStr.toJson();
			
			if (expected != observed) {
				std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
						"message=expect " << expected << " observed " << observed << std::endl;
			}
			
		}

		void testJsonStringEmptyStringShouldReturnEmpty() {
			
			const char * METHOD_NAME = "testJsonStringEmptyStringShouldReturnEmpty";
			
			std::string value("");
			
			JsonString jsonStr(value.c_str());
			std::string expected("\"\"");
			
			std::string observed = jsonStr.toJson();
			
			if (expected != observed) {
				std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
						"message=expect " << expected << " observed " << observed << std::endl;
			}
		}

		void testJsonWstringAddQuotesUnicodeJson() {
			
			const char * METHOD_NAME = "testJsonWstringAddQuotesUnicodeJson";
			
			const uint16_t data[] = {
				0x0030, 0x0031, 0x0032, 0x0033, 0x1020, 0x3040, 0x5060, 0x0
			};
			std::string expected("\"\\u0030\\u0031\\u0032\\u0033\\u1020\\u3040\\u5060\"");
			JsonWstring json(data);
			
			std::string observed = json.toJson();
			
			if (expected != observed) {
				std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
						"message=expect " << expected << " observed " << observed << std::endl;
			}
			
		}

		void testJsonWstringEmptyStringShouldReturnEmpty() {
			
			const char * METHOD_NAME = "testJsonWstringEmptyStringShouldReturnEmpty";
			
			const uint16_t data[] = {
				0x0
			};
			std::string expected("\"\"");
			JsonWstring json(data);
			
			std::string observed = json.toJson();
			
			if (expected != observed) {
				std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
						"message=expect " << expected << " observed " << observed << std::endl;
			}
			
		}

		void testJsonStructShouldReturnSimpleJsHash() {
			
			const char * METHOD_NAME = "testJsonStructShouldReturnSimpleJsHash";
			
			std::string expected("{\"hex\":\"0xabcde\",\"int\":125,\"simple\":\"simple\",\"wstring\":\"\\u0056\\u0060\"}");
			
			JsonStruct js;
			
			JsonString simple("simple");
			js.setValue("simple", &simple);
			
			JsonInt jsInt(125);
			js.setValue("int", &jsInt);
			
			JsonIntHex jsIntHex(0xabcde);
			js.setValue("hex", &jsIntHex);
			
			const uint16_t data[] = {
				0x0056, 0x0060, 0
			};
			JsonWstring wstring(data);
			js.setValue("wstring", &wstring);
			
			std::string observed(js.toJson());
			
			if (expected != observed) {
				std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
						"message=expect " << expected << " observed " << observed << std::endl;
			}
		}

		void testJsonStructShouldReturnSubStructsJsHash() {
			
			const char * METHOD_NAME = "testJsonStructShouldReturnSubStructsJsHash";
			
			// implementation of C++ Map will sort the keys lexicographically
			std::string expected(
				"{"
					"\"hex\":\"0xabcde\","
					"\"int\":125,"
					"\"string\":\"simple\","
					"\"struct\":{"
						"\"check\":\"0x5495904\","
						"\"subint\":126"
					"},"
					"\"wstring\":\"\\u0056\\u0060\""
				"}"
			);
			
			JsonStruct js;
			
			JsonString simple("simple");
			js.setValue("string", &simple);
			
			JsonInt jsInt(125);
			js.setValue("int", &jsInt);
			
			JsonIntHex jsIntHex(0xabcde);
			js.setValue("hex", &jsIntHex);
			
			const uint16_t data[] = {
				0x0056, 0x0060, 0
			};
			JsonWstring wstring(data);
			js.setValue("wstring", &wstring);
			
			JsonStruct subJs;
			
			JsonInt subJsInt(126);
			subJs.setValue("subint", &subJsInt);
			
			JsonIntHex subJsIntHex(0x5495904);
			subJs.setValue("check", &subJsIntHex);
			
			js.setValue("struct", &subJs);
			
			std::string observed(js.toJson());
			
			if (expected != observed) {
				std::cout << "%TEST_FAILED% time=0 testname=" << METHOD_NAME << " (" TESTSUITENAME ") "
						"message=expect " << expected << " observed " << observed << std::endl;
			}
		}

		#define T(X) RUNFUNC(X,TESTSUITENAME)

		void runTest_JsonSerializerTest() {
			std::cout << "%SUITE_STARTING% "TESTSUITENAME << std::endl;
			std::cout << "%SUITE_STARTED%" << std::endl;

			T(testJsonIntPrintDec);
			T(testJsonIntPrintHex);
			T(testJsonStringAddQuotes);
			T(testJsonStringEmptyStringShouldReturnEmpty);
			T(testJsonStructShouldReturnSimpleJsHash);
			T(testJsonStructShouldReturnSubStructsJsHash);
			T(testJsonWstringAddQuotesUnicodeJson);
			T(testJsonWstringEmptyStringShouldReturnEmpty);
			T(testJsonStringWeirdCharsExpectHexIfNonPrintableAndDblQuotes);

			std::cout << "%SUITE_FINISHED% time=0" << std::endl;
		}

	}
}

void runTest_JsonSerializerTest() {
	Tests::JsonSerializer::runTest_JsonSerializerTest();
}
