//
// Created by Nate on 4/22/2017.
//
#include "Analyzer.h"

#ifndef HW7_ITAK_DENIALOFSERVICEANALYZER_H
#define HW7_ITAK_DENIALOFSERVICEANALYZER_H


class DenialOfServiceAnalyzer : protected Analyzer{
public:
    DenialOfServiceAnalyzer(Configuration initConfig);
    ResultSet run(std::istream& in);
private:
    std::map<std::string, std::map<int, int>> inputData;
};


#endif //HW7_ITAK_DENIALOFSERVICEANALYZER_H
