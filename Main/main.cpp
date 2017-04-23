#include <fstream>
#include "DenialOfServiceAnalyzer.h"
#include "PortScanAnalyzer.h"

int main()
{
    Configuration denialConfig;
    denialConfig.insertConfigParam("Timeframe", "2000");
    denialConfig.insertConfigParam("Likely Attack Message Count", "1000");
    denialConfig.insertConfigParam("Possible Attack Message Count", "1500");

    DenialOfServiceAnalyzer denial(denialConfig);

    Configuration portConfig;
    portConfig.insertConfigParam("Likely Attack Port Count", "1000");
    portConfig.insertConfigParam("Possible Attack Port Count", "1500");

    PortScanAnalyzer port(portConfig);

    std::ifstream fin("input.txt");

    //ResultSet denyRS = denial.run(std::cin);
    ResultSet denyRS = denial.run(fin);

    fin.close();

    std::ifstream fin2("input.txt");

    //ResultSet portRS = port.run(std::cin);
    ResultSet portRS = port.run(fin2);

    fin2.close();

    return 0;
}