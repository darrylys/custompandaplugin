#if defined(RUNTEST)
#include "tests/TestInterface.h"
#include <iostream>

void runFunc(const char * testName, void (*fn)(), const char * strTestSuiteName) {
    std::cout << "%TEST_STARTED% " << testName << " (" << strTestSuiteName << ")" << std::endl;
    fn();
    std::cout << "%TEST_FINISHED% time=0 " << testName << " (" << strTestSuiteName << ")" << std::endl;
}

int main() {
	runTest_CsvReaderTest();
	runTest_JsonSerializerTest();
	runTest_LiteralTypeTest();
	runTest_StringTypeTest();
	runTest_UtilsTest();
	runTest_WinApisTest();
	runTest_WinTypeData2JsonSerializerTest();
}

#endif