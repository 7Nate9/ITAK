#include <map>
#include <string>

#ifndef _CONFIGURATION_H_
#define _CONFIGURATION_H_

class Configuration
{
private:
    std::map<std::string, std::string> configParameters;

public:
    std::string getConfigAsString(std::string key);
    int getConfigAsInt(std::string key);
    double getConfigAsDouble(std::string key);
    void insertConfigParam(std::string key, std::string value);
    bool isPresent(std::string key);
};

#endif