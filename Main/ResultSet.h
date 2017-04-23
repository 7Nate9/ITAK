#include <iostream>
#include <string>
#include <vector>
#include <map>

#ifndef HW7_ITAK_RESULTSET_H
#define HW7_ITAK_RESULTSET_H

class ResultSet
{
public:
    void print(std::ostream& out);
    void insertResult(std::string key, std::vector<std::string> value);
    void addToValueVector(std::string key, std::string newValue);
    std::vector<std::string> lookup(std::string key);
private:
    std::map<std::string, std::vector<std::string>> results;
};

#endif