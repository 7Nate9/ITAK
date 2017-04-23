#include "ResultSet.h"

void ResultSet::print(std::ostream& out)
{
    std::map<std::string, std::vector<std::string>>::iterator it = results.begin();

    while(it != results.end())
    {
        out << it->first << ":" << std::endl;
        for (unsigned int i = 0; i < it->second.size(); i++)
        {
            out << "    " << it->second[i] << std::endl;
        }
        it++;
    }
}

void ResultSet::insertResult(std::string key, std::vector<std::string> value)
{
    results.insert(std::make_pair(key, value));
}

void ResultSet::addToValueVector(std::string key, std::string newValue)
{
    results.at(key).push_back(newValue);
}

std::vector<std::string> ResultSet::lookup(std::string key)
{
    return results.at(key);
}