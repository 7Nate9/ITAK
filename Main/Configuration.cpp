#include "Configuration.h"
#include "Utils.h"

std::string Configuration::getConfigAsString(std::string key)
{
    return configParameters[key];
}

int Configuration::getConfigAsInt(std::string key)
{
    return convertStringToInt(configParameters[key]);
}

double Configuration::getConfigAsDouble(std::string key)
{
    return convertStringToDouble(configParameters[key]);
}
void Configuration::insertConfigParam(std::string key, std::string value)
{
    configParameters.insert(std::make_pair(key, value));
}

bool Configuration::isPresent(std::string key)
{
    try {
        configParameters.at(key);
    }
    catch(std::out_of_range)
    {
        return false;
    }

    return true;
}