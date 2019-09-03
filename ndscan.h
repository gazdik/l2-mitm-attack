/**
 * @author      Peter Gazdík <xgazdi03(at)stud.fit.vutbr.cz>
 * @date        15/04/2017
 * @copyright   The MIT License (MIT)
 */

#ifndef PDS_NDSCAN_H
#define PDS_NDSCAN_H

#include "types.h"
#include "pcap.h"
#include "netlib.h"

#include <thread>

namespace pds
{

class ndscan
{
public:
    ndscan(const char *interface);
    ~ndscan();

    void scan();
    std::vector<struct HostAddr> getHosts();

private:
    void init();
    void sendRequests();
    void sendEchoRequest();
    void sendMalformedPacket();
    void receiveReplies();
    void parseReply(const struct pcap_pkthdr *header, const u_char *packet);

private:
    pcap *_pcap;
    InterfaceInfo _interInfo;

    bool _timeout = false;
    std::vector<HostAddr> _hosts;

    std::thread *_sender = nullptr;
    std::thread *_receiver = nullptr;
};

}

#endif //PDS_NDSCAN_H
