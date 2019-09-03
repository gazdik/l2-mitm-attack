/**
 * @author      Peter Gazdík <xgazdi03(at)stud.fit.vutbr.cz>
 * @date        14/04/2017
 * @copyright   The MIT License (MIT)
 */

#include <getopt.h>

#include <iostream>
using namespace std;

#include "netlib.h"
#include "arpscan.h"
#include "ndscan.h"
#include "types.h"
#include "addr.h"

using namespace pds;

const struct option longOptions[] =
        {
                { "help", no_argument, 0, 'h' },
                { "interface", required_argument, 0, 'i' },
                { "file", required_argument, 0, 'f' },
                { 0, 0 , 0, 0 }
        };

const char *helpMsg = "pdf-scanner -i interface -f file\n\n"
        "  -h, --help          prints this help\n"
        "  -i, --interface     interface name\n"
        "  -f, --file          path to the output file\n";

int main(int argc, char *argv[])
{
    const char *interface = nullptr;
    const char *outputFile = nullptr;
    bool help = false;

    // Parse options
    int opt, optIndex;
    while((opt = getopt_long(argc, argv, "hi:f:", longOptions, &optIndex)) != -1) {
        switch (opt) {
            case 'h':
                help = true;
                break;
            case 'i':
                interface = optarg;
                break;
            case 'f':
                outputFile = optarg;
                break;
            default:
                break;
        }
    }

    // Print the help message
    if (help || interface == nullptr || outputFile == nullptr) {
        cout << helpMsg;
        return EXIT_SUCCESS;
    }

    // Get all addresses of given interface
    auto interInfo = pds::getInterfaceInfo(interface);
    cout << interInfo.name << "\n";
    cout << "  inet " << interInfo.ipv4.address.textForm()
         << " netmask " << interInfo.ipv4.netmask.textForm() << "\n";
    for (auto ipv6: interInfo.ipv6global) {
        cout << "  inet6 " << ipv6.address.textForm()
             << " netmask " << ipv6.netmask.textForm() << "\n";
    }
    cout << "  ether " << interInfo.mac.textForm() << "\n";

    std::vector<HostAddr> hosts;

    auto arpscan = pds::arpscan(interface);
    arpscan.scan();

    auto ndscan = pds::ndscan(interface);
    ndscan.scan();

    hosts = arpscan.getHosts();
    auto hosts6 = ndscan.getHosts();
    hosts.insert(hosts.end(), hosts6.begin(), hosts6.end());

    for (auto &host: hosts) {
        cout << "MAC: " << host.eth.textForm() << " IP: " << host.net.textForm()
             << endl;
    }

    return EXIT_SUCCESS;
}