#include <fstream>
#include "DenialOfServiceAnalyzer.h"
#include "PortScanAnalyzer.h"

/*This use case probably won't do much, do to limitations on my hand-entered inputs.
 * Essentially, this program will run two attack analyzers on an access log, and will report if any attacks occurred, and from which IP address they came.
 * */

int main()
{
    Configuration denialConfig;
    denialConfig.insertConfigParam("Timeframe", "10");
    denialConfig.insertConfigParam("Likely Attack Message Count", "10");
    denialConfig.insertConfigParam("Possible Attack Message Count", "5");

    DenialOfServiceAnalyzer denial(denialConfig);

    Configuration portConfig;
    portConfig.insertConfigParam("Likely Attack Port Count", "10");
    portConfig.insertConfigParam("Possible Attack Port Count", "5");

    PortScanAnalyzer port(portConfig);

    std::ifstream fin("input.txt");

    ResultSet denyRS = denial.run(fin);

    fin.close();

    std::ifstream fin2("input.txt");

    ResultSet portRS = port.run(fin2);

    fin2.close();

    std::cout << "Denial of Service:" << std::endl;
    denyRS.print(std::cout);

    std::cout << "Port Scan:" << std::endl;
    portRS.print(std::cout);

    return 0;
}