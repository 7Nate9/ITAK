//
// Created by Nate on 4/22/2017.
//

#include "DenialOfServiceAnalyzer.h"
#include "Utils.h"

DenialOfServiceAnalyzer::DenialOfServiceAnalyzer(Configuration initConfig)
{
    if (!initConfig.isPresent("Timeframe"))
    {
        throw "Denial of Service Analyzer requires Timeframe config parameter.";
    }
    if (!initConfig.isPresent("Likely Attack Message Count"))
    {
        throw "Denial of Service Analyzer requires Likely Attack Message Count config parameter.";
    }
    if (!initConfig.isPresent("Possible Attack Message Count"))
    {
        throw "Denial of Service Analyzer requires Possible Attack Message Count config parameter.";
    }

    config = initConfig;
}

ResultSet DenialOfServiceAnalyzer::run(std::istream& in)
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

        int timeStamp = convertStringToInt(lineItems[0]);
        std::string srcAddress = lineItems[1];
        int srcPort = convertStringToInt(lineItems[2]);
        int desPort = convertStringToInt(lineItems[3]);

        try {
            inputData.at(srcAddress);
        }
        catch(std::out_of_range)
        {
            std::map<int, int> timeStampToCount;

            inputData.insert(std::make_pair(srcAddress, timeStampToCount));
        }

        try {
            inputData.at(srcAddress).at(timeStamp) += 1;
        }
        catch(std::out_of_range)
        {
            inputData.at(srcAddress).insert(std::make_pair(timeStamp, 1));
        }
    }

    ResultSet results;
    results.insertResult("Likely Attackers", {});
    results.insertResult("Possible Attackers", {});
    results.insertResult("Attack Periods", {});
    results.insertResult("Timeframe", {});

    int timeframe = config.getConfigAsInt("Timeframe");
    int likelyThreshold = config.getConfigAsInt("Likely Attack Message Count");
    int possibleThreshold = config.getConfigAsInt("Possible Attack Message Count");

    results.addToValueVector("Timeframe", std::to_string(timeframe));

    for (std::map<std::string, std::map<int, int>>::iterator ipIt = inputData.begin(); ipIt != inputData.end(); ipIt++)
    {
        bool likely = false;
        bool possible = false;

        for (std::map<int, int>::iterator timeIt = (ipIt->second).begin(); timeIt != (ipIt->second).end(); timeIt++)
        {
            unsigned int messageCount = 0;

            for (std::map<int, int>::iterator timeIt2 = timeIt; timeIt2->first < timeIt->first + timeframe && timeIt2 != (ipIt->second).end(); timeIt2++)
            {
                messageCount += timeIt2->second;
            }

            if (messageCount >= likelyThreshold)
            {
                likely = true;
                results.addToValueVector("Attack Periods", std::to_string(timeIt->first) + "-" + std::to_string(timeIt->first + timeframe));
            }
            else if (messageCount >= possibleThreshold)
            {
                possible = true;
                results.addToValueVector("Attack Periods", std::to_string(timeIt->first) + "-" + std::to_string(timeIt->first + timeframe));
            }
        }

        if (likely)
        {
            results.addToValueVector("Likely Attackers", ipIt->first);
        }
        else if (possible)
        {
            results.addToValueVector("Possible Attackers", ipIt->first);
        }
    }

    return results;
}