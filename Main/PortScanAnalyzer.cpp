//
// Created by Nate on 4/22/2017.
//

#include "PortScanAnalyzer.h"
#include "Utils.h"

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
    std::string inputLine;
    while(std::getline(in, inputLine))
    {
        std::string lineItems[4];
        split(inputLine, ',', lineItems, 4);

        //Maybe not necessary?
        //for (unsigned int i = 0; i < 4; i++)
        //{
        //    trim(lineItems[i]);
        //}
        //end

        std::string timeStamp = lineItems[0];
        std::string srcAddress = lineItems[1];
        int srcPort = convertStringToInt(lineItems[2]);
        int desPort = convertStringToInt(lineItems[3]);

        try {
            inputData.at(srcAddress);
        }
        catch(std::out_of_range)
        {
            std::map<int, std::string> desPortToTime;

            inputData.insert(std::make_pair(srcAddress, desPortToTime));
        }

        try {
            inputData.at(srcAddress).at(desPort);
        }
        catch(std::out_of_range)
        {
            inputData.at(srcAddress).insert(std::make_pair(desPort, timeStamp));
        }
    }

    ResultSet results;
    results.insertResult("Likely Attackers", {});
    results.insertResult("Possible Attackers", {});
    results.insertResult("Port Count", {});

    int likelyThreshold = config.getConfigAsInt("Likely Attack Port Count");
    int possibleThreshold = config.getConfigAsInt("Possible Attack Port Count");

    std::map<std::string, std::map<int, std::string>>::iterator it = inputData.begin();
    while(it != inputData.end())
    {
        std::string src = it->first;
        int portsMessaged = it->second.size();

        if (portsMessaged >= likelyThreshold)
        {
            results.addToValueVector("Likely Attackers", src);
        }
        else if (portsMessaged >= possibleThreshold)
        {
            results.addToValueVector("Possible Attackers", src);
        }

        it++;
    }

    return results;
}