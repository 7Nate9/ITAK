//
// Created by Nate on 4/22/2017.
//
#include "Analyzer.h"

#ifndef HW7_ITAK_PORTSCANANALYZER_H
#define HW7_ITAK_PORTSCANANALYZER_H


class PortScanAnalyzer : private Analyzer
{
public:
    PortScanAnalyzer(Configuration initConfig);
    ResultSet run(std::istream& in);
};


#endif //HW7_ITAK_PORTSCANANALYZER_H
