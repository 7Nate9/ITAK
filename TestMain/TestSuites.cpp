//
// Created by Nate on 4/22/2017.
//
#include <sstream>

#include "TestSuites.h"
#include "../Main/ResultSet.h"
#include "../Main/Configuration.h"

void TestSuites::testSuites(std::ostream& out)
{
    testResultSet(out);
    testConfiguration(out);
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