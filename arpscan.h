/**
 * @author      Peter Gazdík <xgazdi03(at)stud.fit.vutbr.cz>
 * @date        15/04/2017
 * @copyright   The MIT License (MIT)
 */

#ifndef PDS_ARPSCAN_H
#define PDS_ARPSCAN_H

#include "types.h"
#include "pcap.h"
#include "netlib.h"

#include <vector>
#include <thread>

namespace pds
{

class arpscan
{
public:
    arpscan(const char *interface);
    ~arpscan();

    void scan();
    std::vector<HostAddr> getHosts();

private:
    void init();
    void sendRequests();
    void receiveReplies();
    void parseReply(const struct pcap_pkthdr *header, const u_char *packet);

private:
    pcap *_pcap;
    InterfaceInfo _interInfo;
    std::uint32_t _firstAddr;
    std::uint32_t _lastAddr;

    bool _timeout = false;
    std::vector<HostAddr> _hosts;

    std::thread *_sender = nullptr;
    std::thread *_receiver = nullptr;
};

} // namespace pds


#endif //PDS_ARPSCAN_H
