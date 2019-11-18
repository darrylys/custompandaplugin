/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   UtilsTest.cpp
 * Author: darryl
 *
 * Created on November 7, 2018, 11:23 PM
 */

#include <stdlib.h>
#include <iostream>

/*
 * Simple C++ Test Suite
 */

void test1() {
    std::cout << "UtilsTest test 1" << std::endl;
}

void test2() {
    std::cout << "UtilsTest test 2" << std::endl;
    std::cout << "%TEST_FAILED% time=0 testname=test2 (UtilsTest) message=error message sample" << std::endl;
}

void runTest_UtilsTest() {
    std::cout << "%SUITE_STARTING% UtilsTest" << std::endl;
    std::cout << "%SUITE_STARTED%" << std::endl;

	/*
    std::cout << "%TEST_STARTED% test1 (UtilsTest)" << std::endl;
    test1();
    std::cout << "%TEST_FINISHED% time=0 test1 (UtilsTest)" << std::endl;

    std::cout << "%TEST_STARTED% test2 (UtilsTest)\n" << std::endl;
    test2();
    std::cout << "%TEST_FINISHED% time=0 test2 (UtilsTest)" << std::endl;
	*/
 
    std::cout << "%SUITE_FINISHED% time=0" << std::endl;
}

