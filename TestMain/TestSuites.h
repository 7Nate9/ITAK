//
// Created by Nate on 4/22/2017.
//

#include <iostream>

#ifndef HW7_ITAK_TESTMAIN_H
#define HW7_ITAK_TESTMAIN_H


class TestSuites {
public:
    void testSuites(std::ostream& out);

private:
    void testResultSet(std::ostream& out);
    void testConfiguration(std::ostream& out);
    void testDenialOfServiceAnalyzer(std::ostream& out);
    void testPortScanAnalyzer(std::ostream& out);
};


#endif //HW7_ITAK_TESTMAIN_H
