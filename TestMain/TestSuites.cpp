//
// Created by Nate on 4/22/2017.
//
#include <sstream>
#include <fstream>

#include "TestSuites.h"
#include "../Main/ResultSet.h"
#include "../Main/Configuration.h"
#include "../Main/DenialOfServiceAnalyzer.h"
#include "../Main/PortScanAnalyzer.h"
#include "../Main/Utils.h"

void TestSuites::testSuites(std::ostream& out)
{
    testResultSet(out);
    testConfiguration(out);
    testDenialOfServiceAnalyzer(out);
    testPortScanAnalyzer(out);
}

void TestSuites::testResultSet(std::ostream& out)
{
    out  << std::endl << "Testing ResultSet:" << std::endl;
    ResultSet results;
    results.insertResult("Key 1", {"Value", "1"});
    results.insertResult("Key 2", {"Value", "2"});
    results.insertResult("Key 3", {"Value", "3"});
    results.insertResult("Key 4", {"Value", "4"});

    std::stringstream sout;

    results.print(sout);

    std::stringstream expected;

    expected << "Key 1:" << std::endl << "    " << "Value" << std::endl << "    " << "1" << std::endl;
    expected << "Key 2:" << std::endl << "    " << "Value" << std::endl << "    " << "2" << std::endl;
    expected << "Key 3:" << std::endl << "    " << "Value" << std::endl << "    " << "3" << std::endl;
    expected << "Key 4:" << std::endl << "    " << "Value" << std::endl << "    " << "4" << std::endl;

    if (sout.str() != expected.str()) {
        out << "ResultSet::insert failed." << std::endl;
    }
}

void TestSuites::testConfiguration(std::ostream& out)
{
    out << std::endl << "Testing Configuration:" << std::endl;

    Configuration config;

    config.insertConfigParam("key1", "1");
    config.insertConfigParam("key2", "2");
    config.insertConfigParam("key3", "3");
    config.insertConfigParam("keyPi", "3.14159");

    out << "Testing Configuration::getConfigAsString:" << std::endl;
    if (config.getConfigAsString("key1") != "1")
    {
        out << "Configuration::getConfigAsString failed. Expected 1, got " << config.getConfigAsString("key1") << std::endl;
    }

    out << "Testing Configuration::getConfigAsInt:" << std::endl;
    if (config.getConfigAsInt("key1") != 1)
    {
        out << "Configuration::getConfigAsInt failed. Expected 1, got " << config.getConfigAsInt("key1") << std::endl;
    }

    out << "Testing Configuration::getConfigAsDouble:" << std::endl;
    if (config.getConfigAsDouble("keyPi") != 3.14159)
    {
        out << "Configuration::getConfigAsDouble failed. Expected 3.14159, got " << config.getConfigAsDouble("keyPi") << std::endl;
    }
}

void TestSuites::testDenialOfServiceAnalyzer(std::ostream& out)
{
    out << std::endl << "Testing DenialOfServiceAnalyzer:" << std::endl;

    Configuration config;
    config.insertConfigParam("Timeframe", "10");
    config.insertConfigParam("Likely Attack Message Count", "10");
    config.insertConfigParam("Possible Attack Message Count", "5");

    Configuration badConfig1;
    badConfig1.insertConfigParam("Likely Attack Message Count", "10");
    badConfig1.insertConfigParam("Possible Attack Message Count", "5");

    Configuration badConfig2;
    badConfig2.insertConfigParam("Timeframe", "10");
    badConfig2.insertConfigParam("Possible Attack Message Count", "5");

    Configuration badConfig3;
    badConfig2.insertConfigParam("Timeframe", "10");
    badConfig1.insertConfigParam("Likely Attack Message Count", "10");

    try
    {
        DenialOfServiceAnalyzer badDenial1(badConfig1);
        out << "Denial of Service fails on initialization: Should not be able to initialize without Timeframe." << std::endl;
    }
    catch(char const* e)
    {
    }

    try
    {
        DenialOfServiceAnalyzer badDenial2(badConfig2);
        out << "Denial of Service fails on initialization: Should not be able to initialize without Likely Attack Message Count." << std::endl;
    }
    catch(char const* e)
    {
    }

    try
    {
        DenialOfServiceAnalyzer badDenial3(badConfig3);
        out << "Denial of Service fails on initialization: Should not be able to initialize without Possible Attack Message Count." << std::endl;
    }
    catch(char const* e)
    {
    }

    DenialOfServiceAnalyzer denial(config);

    std::ifstream fin("testInput.txt");

    ResultSet results = denial.run(fin);

    fin.close();

    if (!ipIsInResults(results, "Likely Attackers", "1.1.1.1"));
    {
        out << "Denial of Service fails on Likely Attackers: 1.1.1.1 should be present, but is not." << std::endl;
    }

    if (!ipIsInResults(results, "Likely Attackers", "6.6.6.6"));
    {
        out << "Denial of Service fails on Likely Attackers: 6.6.6.6 should be present, but is not." << std::endl;
    }

    if (!ipIsInResults(results, "Possible Attackers", "2.2.2.2"))
    {
        out << "Denial of Service fails on Possible Attackers: 2.2.2.2 should be present, but is not." << std::endl;
    }

    if (!ipIsInResults(results, "Possible Attackers", "7.7.7.7"))
    {
        out << "Denial of Service fails on Possible Attackers: 7.7.7.7 should be present, but is not." << std::endl;
    }

    for (unsigned int i = 0; i < results.lookup("Likely Attackers").size(); i++)
    {
        if (results.lookup("Likely Attackers")[i] != "1.1.1.1" && results.lookup("Likely Attackers")[i] != "6.6.6.6")
        {
            out << "Denial of Service fails on Likely Attackers: " << results.lookup("Likely Attackers")[i] << " should not be present, but is." <<std::endl;
        }
    }

    for (unsigned int i = 0; i < results.lookup("Possible Attackers").size(); i++)
    {
        if (results.lookup("Possible Attackers")[i] != "2.2.2.2" && results.lookup("Possible Attackers")[i] != "7.7.7.7")
        {
            out << "Denial of Service fails on Possible Attackers: " << results.lookup("Possible Attackers")[i] << " should not be present, but is." <<std::endl;
        }
    }
}

void TestSuites::testPortScanAnalyzer(std::ostream& out)
{
    out << std::endl << "Testing PortScanAnalyzer:" << std::endl;

    Configuration config;
    config.insertConfigParam("Likely Attack Port Count", "10");
    config.insertConfigParam("Possible Attack Port Count", "5");

    Configuration badConfig1;
    badConfig1.insertConfigParam("Possible Attack Port Count", "5");

    Configuration badConfig2;
    badConfig2.insertConfigParam("Likely Attack Port Count", "5");

    try {
        PortScanAnalyzer badPort1(badConfig1);
        out << "Port Scan fails on initialization. Should not be able to initialize without Likely Attack Port Count." << std::endl;
    }
    catch(char const* e)
    {

    }

    try {
        PortScanAnalyzer badPort2(badConfig2);
        out << "Port Scan fails on initialization. Should not be able to initialize without Possible Attack Port Count." << std::endl;
    }
    catch(char const* e)
    {

    }

    PortScanAnalyzer port(config);

    std::ifstream fin("testInput.txt");

    ResultSet results = port.run(fin);

    fin.close();

    if (!ipIsInResults(results, "Likely Attackers", "1.1.1.2"));
    {
        out << "Port Scan fails on Likely Attackers: 1.1.1.2 should be present, but is not." << std::endl;
    }

    if (!ipIsInResults(results, "Likely Attackers", "6.6.6.6"));
    {
        out << "Port Scan fails on Likely Attackers: 6.6.6.6 should be present, but is not." << std::endl;
    }

    if (!ipIsInResults(results, "Possible Attackers", "2.2.2.3"))
    {
        out << "Port Scan fails on Possible Attackers: 2.2.2.3 should be present, but is not." << std::endl;
    }

    if (!ipIsInResults(results, "Possible Attackers", "7.7.7.7"))
    {
        out << "Port Scan fails on Possible Attackers: 7.7.7.7 should be present, but is not." << std::endl;
    }

    for (unsigned int i = 0; i < results.lookup("Likely Attackers").size(); i++)
    {
        if (results.lookup("Likely Attackers")[i] != "1.1.1.2" && results.lookup("Likely Attackers")[i] != "6.6.6.6")
        {
            out << "Port Scan fails on Likely Attackers: " << results.lookup("Likely Attackers")[i] << " should not be present, but is." <<std::endl;
        }
    }

    for (unsigned int i = 0; i < results.lookup("Possible Attackers").size(); i++)
    {
        if (results.lookup("Possible Attackers")[i] != "2.2.2.3" && results.lookup("Possible Attackers")[i] != "7.7.7.7")
        {
            out << "Port Scan fails on Possible Attackers: " << results.lookup("Possible Attackers")[i] << " should not be present, but is." <<std::endl;
        }
    }
}