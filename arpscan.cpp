/**
 * @author      Peter Gazdík <xgazdi03(at)stud.fit.vutbr.cz>
 * @date        15/04/2017
 * @copyright   The MIT License (MIT)
 */

#include "arpscan.h"

#include <netinet/if_ether.h>
#include <netinet/ether.h>

#include <iostream>
#include <cstring>
#include <chrono>
#include <stdexcept>

using namespace std;
using namespace std::literals::chrono_literals;

namespace pds
{


arpscan::arpscan(const char *interface)
{
    _pcap = new pcap(interface);
    _interInfo = getInterfaceInfo(interface);

    init();
}

arpscan::~arpscan()
{
    delete _pcap;
    delete _sender;
    delete _receiver;
}

void arpscan::scan()
{
    _sender = new thread(&arpscan::sendRequests, this);
    _receiver = new thread(&arpscan::receiveReplies, this);
}

std::vector<HostAddr> arpscan::getHosts()
{
    if (_sender) _sender->join();
    if (_receiver) _receiver->join();

    return _hosts;
}

void arpscan::sendRequests()
{
    // Allocate memory for an arp message
    const size_t MSG_LEN = ETH_HDR_LEN + ARP_MSG_LEN;
    uint8_t *msg = new uint8_t[MSG_LEN];
    struct eth_hdr *ethHdr = (struct eth_hdr *) msg;
    struct arp_msg *arpMsg = (struct arp_msg *) (msg + ETH_HDR_LEN);

    // Set the ethernet header entries
    ethHdr->eth_type = htons(ETH_P_ARP);
    memcpy(&ethHdr->eth_dst, ether_aton("ff:ff:ff:ff:ff:ff"), ETH_ADDR_LEN);
    ethHdr->eth_src = *_interInfo.mac.getMAC();

    // Set the constant entries in ARP message
    struct eth_addr sha = ethHdr->eth_src;
    struct ip4_addr spa = _interInfo.ipv4.address.getIPv4();
    struct ip4_addr tpa;
    fillARPRequest(arpMsg, &sha, &spa, &tpa);

    // Send ARP requests in loop
    uint32_t currAddr = _firstAddr;
    do {
        tpa.data = currAddr;
        arpMsg->tpa = tpa;

        _pcap->sendpacket(msg, MSG_LEN);

        currAddr = htonl(ntohl(currAddr) + 1);
    } while(ntohl(currAddr) <= ntohl(_lastAddr));

    delete msg;

    this_thread::sleep_for(2s);
    _timeout = true;
}

void arpscan::receiveReplies()
{
    // TODO filter messages only for me
    static const string filter("ether proto \\arp");
    _pcap->setFilter(filter.c_str());

    auto callback = [=](const struct pcap_pkthdr *header, const u_char *packet){
        parseReply(header, packet);
    };

    _pcap->setNonBlock(true);

    while (not _timeout) {
        _pcap->dispatch(callback);
    }
}

void arpscan::init()
{
    uint32_t hostAddr = _interInfo.ipv4.address.getIPv4().data;
    uint32_t netmask =  _interInfo.ipv4.netmask.getIPv4().data;

    uint32_t netAddr = htonl(ntohl(hostAddr) & ntohl(netmask));
    uint32_t broadcastAddr = htonl(ntohl(hostAddr) | ~ntohl(netmask));

    _firstAddr = htonl(ntohl(netAddr) + 1);
    _lastAddr = htonl(ntohl(broadcastAddr) - 1);
}

void
arpscan::parseReply(const struct pcap_pkthdr *header, const u_char *packet)
{
    static const size_t MSG_LEN = ETH_HDR_LEN + ARP_MSG_LEN;
    struct eth_hdr *ethHdr = (struct eth_hdr *) packet;
    struct arp_msg *arpMsg = (struct arp_msg *) (packet + ETH_HDR_LEN);

    if (ntohs(arpMsg->op) != 2)
        return;

    HostAddr host;
    host.net.setAddr(AF_INET, &arpMsg->spa);
    host.eth.setAddr(AF_PACKET, &arpMsg->sha);

    _hosts.push_back(host);
}

}