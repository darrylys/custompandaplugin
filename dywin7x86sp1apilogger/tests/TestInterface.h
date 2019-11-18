#ifndef TESTINTERFACE_H
#define TESTINTERFACE_H

void runTest_CsvReaderTest();
void runTest_JsonSerializerTest();
void runTest_LiteralTypeTest();
void runTest_StringTypeTest();
void runTest_UtilsTest();
void runTest_WinApisTest();
void runTest_WinTypeData2JsonSerializerTest();

void runFunc(const char * testName, void (*fn)(), const char * strTestSuiteName);
#define RUNFUNC(X,TS) runFunc(#X,X,TS)

#endif