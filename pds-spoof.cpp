/**
 * @author      Peter Gazdík <xgazdi03(at)stud.fit.vutbr.cz>
 * @date        17/04/2017
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
#include "spoof.h"
#include "arpspoof.h"
#include "ndspoof.h"

using namespace pds;

#include <arpa/inet.h>
#include <netinet/ether.h>
#include <time.h>
#include <signal.h>


#include <cstring>
#include <cmath>
using namespace std;

static bool stopFlag = false;

const struct option longOptions[] =
        {
                { "help", no_argument, 0, 'h' },
                { "interface", required_argument, 0, 'i' },
                { "protocol", required_argument, 0, 'p'},
                { "time", required_argument, 0, 't' },
                { "victim1ip", required_argument, 0, 'a' },
                { "victim1mac", required_argument, 0, 'b' },
                { "victim2ip", required_argument, 0, 'c' },
                { "victim2mac", required_argument, 0, 'd' },
                { 0, 0 , 0, 0 }
        };

const char *helpMsg = "pdf-scanner -i interface -f file\n\n"
        "  -h, --help          prints this help\n"
        "  -i, --interface     interface name\n"
        "  -t, --time          interval to send ARP/NDP messages\n"
        "  -p, --protocol      arp or ndp\n"
        "  --victim1ip         ip address of the first victim\n"
        "  --victim1mac        mac address of the first victim\n"
        "  --victim2ip         ip address of the second victim\n"
        "  --victim2mac        mac address of the second victim\n";

void sig_handler(int signal)
{
    if (signal == SIGINT) {
        stopFlag = true;
    }
}

int main(int argc, char *argv[])
{
    const char *interface = nullptr;
    int interval = -1;
    const char *protocol = nullptr;
    const char *victim1ip = nullptr;
    const char *victim2ip = nullptr;
    const char *victim1mac = nullptr;
    const char *victim2mac = nullptr;
    bool help = false;

    // Parse options
    int opt, optIndex;
    while((opt = getopt_long_only(argc, argv, "hi:p:t:a:b:c:d:", longOptions, &optIndex)) != -1) {
        switch (opt) {
            case 'h':
                help = true;
                break;
            case 'i':
                interface = optarg;
                break;
            case 't':
                interval = atoi(optarg);
                break;
            case 'p':
                protocol = optarg;
                break;
            case 'a':
                victim1ip = optarg;
                break;
            case 'b':
                victim1mac = optarg;
                break;
            case 'c':
                victim2ip = optarg;
                break;
            case 'd':
                victim2mac = optarg;
                break;
            default:
                break;
        }
    }

    // Print the help message
    if (help) {
        cout << helpMsg;
        return EXIT_SUCCESS;
    }

    // Missing arguments
    if (interface == nullptr || interval == -1 || protocol == nullptr
        || victim1ip == nullptr || victim1mac == nullptr
        || victim2ip == nullptr || victim2mac == nullptr )
    {
        cerr << "One or more required arguments are missing." << endl;
        cout << helpMsg;
        return EXIT_FAILURE;
    }

    // Unsupported protocol
    if (strcmp("arp", protocol) != 0 && strcmp("ndp", protocol) != 0) {
        cerr << "Unsupported protocol." << endl;
        cout << helpMsg;
        return EXIT_FAILURE;
    }

    HostAddr victim1, victim2;

    int af_ip = protocol[0] == 'n' ? AF_INET6 : AF_INET;
    victim1.eth.setFromString(AF_PACKET, victim1mac);
    victim1.net.setFromString(af_ip, victim1ip);
    victim2.eth.setFromString(AF_PACKET, victim2mac);
    victim2.net.setFromString(af_ip, victim2ip);

    spoof *spoof;
    if (protocol[0] == 'a')
        spoof = new arpspoof();
    else
        spoof = new ndspoof();

    spoof->setInterface(interface);
    spoof->setVictims(victim1, victim2);
    spoof->setInterval(interval);
    spoof->init();

    // Time interval
    struct timespec sleepInterval;
    sleepInterval.tv_sec = (__time_t ) floor(interval / 1000);
    sleepInterval.tv_nsec = (interval - sleepInterval.tv_sec * 1000) * 1000000;

    // Register the signal handler for SIGINT
    signal(SIGINT, sig_handler);

    while(not stopFlag) {
        spoof->poisoneCache();

        nanosleep(&sleepInterval, nullptr);
    }

    spoof->stopSpoofing();

    return EXIT_SUCCESS;
}