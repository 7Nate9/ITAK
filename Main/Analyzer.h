#include "Configuration.h"
#include "ResultSet.h"
#include <iostream>

#ifndef _ANALYZER_H_
#define _ANALYZER_H_

class Analyzer
{
public:
    virtual ResultSet run(std::istream in) = 0;
    Analyzer();
protected:
    Configuration config;
};

#endif