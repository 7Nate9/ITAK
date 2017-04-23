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
        std::cout << inputLine << std::endl;

        std::string lineItems[4];
        split(inputLine, ',', lineItems, 4);

        //Maybe not necessary?
        for (unsigned int i = 0; i < 4; i++)
        {
            trim(lineItems[i]);
        }
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

    std::map<std::string, std::map<int, int>>::iterator it = inputData.begin();
    while(it != inputData.end())
    {
        std::map<int, int>::iterator it2 = (it->second).begin();
        while(it2 != (it->second).end())
        {
            unsigned int messageCount = 0;

            for (std::map<int, int>::iterator it3 = it2; it3->first < it2->first + timeframe && it3 != (it->second).end(); it3++)
            {
                messageCount += it3->second;
            }

            if (messageCount >= likelyThreshold)
            {
                results.addToValueVector("Likely Attacker", it->first);
            }
            else if (messageCount >= possibleThreshold)
            {
                results.addToValueVector("Possible Attackers", it->first);
            }

            it2++;
        }

        it++;
    }
}