/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   newsimpletest.cpp
 * Author: darryl
 *
 * Created on November 3, 2018, 11:14 AM
 */

#include <stdlib.h>
#include <iostream>
#include "TestInterface.h"
#include "CsvReader.h"

namespace Tests {
	namespace CsvReader {

		#define TESTNAME "CsvReaderTest"

		/*
		 * Simple C++ Test Suite
		 */

		void testParse_csv_ABCDE() {
			const char* str = "A,B,C,D,E";
			std::vector<std::string> cells;
			bool result = csvreader::parse_csv(str, cells);
			if (!result) {
				std::cout << "%TEST_FAILED% time=0 testname=testParse_csv_ABCDE (" TESTNAME ") "
						"message=return expect true got false" << std::endl;
			}
			int size = cells.size();
			if (size != 5) {
				std::cout << "%TEST_FAILED% time=0 testname=testParse_csv_ABCDE (" TESTNAME ") "
						"message=Expected size 5 got " << size << std::endl;
			}
			const char * expected[] = {
				"A", "B", "C", "D", "E"
			};
			for (int i=0; i<size; ++i) {
				if (cells[i] != expected[i]) {
					std::cout << "%TEST_FAILED% time=0 testname=testParse_csv_ABCDE "
							"(" TESTNAME ") message=Expected " << expected[i] << " got " << cells[i] << std::endl;
				}
			}
			
		}

		void testParse_csv_ABcDE() {
			const char* str = "A,B,,D,E";
			std::vector<std::string> cells;
			bool result = csvreader::parse_csv(str, cells);
			if (!result) {
				std::cout << "%TEST_FAILED% time=0 testname=testParse_csv_ABcDE (" TESTNAME ") "
						"message=return expect true got false" << std::endl;
			}
			int size = cells.size();
			if (size != 5) {
				std::cout << "%TEST_FAILED% time=0 testname=testParse_csv_ABcDE (" TESTNAME ") "
						"message=Expected size 5 got " << size << std::endl;
			}
			const char * expected[] = {
				"A", "B", "", "D", "E"
			};
			for (int i=0; i<size; ++i) {
				if (cells[i] != expected[i]) {
					std::cout << "%TEST_FAILED% time=0 testname=testParse_csv_ABcDE "
							"(" TESTNAME ") message=Expected " << expected[i] << " got " << cells[i] << std::endl;
				}
			}
			
		}

		void testParse_csv_ABCDc() {
			const char* str = "A,B,C,D,";
			std::vector<std::string> cells;
			bool result = csvreader::parse_csv(str, cells);
			if (!result) {
				std::cout << "%TEST_FAILED% time=0 testname=testParse_csv_ABCDc (" TESTNAME ") "
						"message=return expect true got false" << std::endl;
			}
			int size = cells.size();
			if (size != 5) {
				std::cout << "%TEST_FAILED% time=0 testname=testParse_csv_ABCDc (" TESTNAME ") "
						"message=Expected size 5 got " << size << std::endl;
			}
			const char * expected[] = {
				"A", "B", "C", "D", ""
			};
			for (int i=0; i<size; ++i) {
				if (cells[i] != expected[i]) {
					std::cout << "%TEST_FAILED% time=0 testname=testParse_csv_ABCDc "
							"(" TESTNAME ") message=Expected " << expected[i] << " got " << cells[i] << std::endl;
				}
			}
			
		}

		void testParse_csv_cBCDE() {
			const char* str = ",B,C,D,E";
			std::vector<std::string> cells;
			bool result = csvreader::parse_csv(str, cells);
			if (!result) {
				std::cout << "%TEST_FAILED% time=0 testname=testParse_csv_cBCDE (" TESTNAME ") "
						"message=return expect true got false" << std::endl;
			}
			int size = cells.size();
			if (size != 5) {
				std::cout << "%TEST_FAILED% time=0 testname=testParse_csv_cBCDE (" TESTNAME ") "
						"message=Expected size 5 got " << size << std::endl;
			}
			const char * expected[] = {
				"", "B", "C", "D", "E"
			};
			for (int i=0; i<size; ++i) {
				if (cells[i] != expected[i]) {
					std::cout << "%TEST_FAILED% time=0 testname=testParse_csv_cBCDE "
							"(" TESTNAME ") message=Expected " << expected[i] << " got " << cells[i] << std::endl;
				}
			}
			
		}

		void runTest_CsvReaderTest() {
			std::cout << "%SUITE_STARTING% " TESTNAME << std::endl;
			std::cout << "%SUITE_STARTED%" << std::endl;

			std::cout << "%TEST_STARTED% testParse_csv (" TESTNAME ")" << std::endl;
			testParse_csv_ABCDE();
			testParse_csv_ABcDE();
			testParse_csv_ABCDc();
			testParse_csv_cBCDE();
			std::cout << "%TEST_FINISHED% time=0 testParse_csv (" TESTNAME ")" << std::endl;

			std::cout << "%SUITE_FINISHED% time=0" << std::endl;
		}
				
	}
}

void runTest_CsvReaderTest() {
	Tests::CsvReader::runTest_CsvReaderTest();
}