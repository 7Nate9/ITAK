cmake_minimum_required(VERSION 3.6)
project(HW7___ITAK)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES Main/DenialOfServiceAnalyzer.cpp Main/DenialOfServiceAnalyzer.h Main/PortScanAnalyzer.cpp Main/PortScanAnalyzer.h Main/Analyzer.h Main/Configuration.cpp Main/Configuration.h Main/ResultSet.cpp Main/ResultSet.h Main/Utils.cpp Main/Utils.h Main/input.txt)
add_executable(Main Main/main.cpp ${SOURCE_FILES} ${Main/main.cpp})

set(TEST_FILES
        TestMain/TestSuites.cpp TestMain/TestSuites.h TestMain/testMain.cpp TestMain/testInput.txt)

add_executable(TestMain TestMain/testMain.cpp ${SOURCE_FILES} ${TEST_FILES})