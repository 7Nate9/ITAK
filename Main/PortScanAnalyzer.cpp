//
// Created by Nate on 4/22/2017.
//

#include "PortScanAnalyzer.h"

PortScanAnalyzer::PortScanAnalyzer(Configuration initConfig)
{
    if (!initConfig.isPresent("Likely Attack Port Count"))
    {
        throw "Port Scan Analyzer requires Likely Attack Port Count config parameter.";
    }
    if (!initConfig.isPresent("Possible Attack Port Count"))
    {
        throw "Port Scan Analyzer requires Possible Attack Port Count config parameter.";
    }

    config = initConfig;
}

ResultSet PortScanAnalyzer::run(std::istream& in)
{
    ResultSet results;
    results.insertResult("Likely Attackers", {"?"});
    results.insertResult("Possible Attackers", {"?"});
    results.insertResult("Port Count", {"?"});
}