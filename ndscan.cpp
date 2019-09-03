/**
 * @author      Peter Gazdík <xgazdi03(at)stud.fit.vutbr.cz>
 * @date        15/04/2017
 * @copyright   The MIT License (MIT)
 */

#include "ndscan.h"

#include "checksum.h"
#include "headers.h"

#include <linux/if_ether.h>

#include <string>
#include <chrono>
#include <iostream>

using namespace std;
using namespace std::literals::chrono_literals;

namespace pds
{

static const uint16_t ECHO_ID = 42;

ndscan::ndscan(const char* interface)
{
    _pcap = new pcap(interface, true);
    _interInfo = getInterfaceInfo(interface);

    init();
}

ndscan::~ndscan()
{
}

void ndscan::scan()
{
    _sender = new thread(&ndscan::sendRequests, this);
    _receiver = new thread(&ndscan::receiveReplies, this);
}

std::vector<struct HostAddr> ndscan::getHosts()
{
    if (_sender) _sender->join();
    if (_receiver) _receiver->join();

    return _hosts;
}

void ndscan::init()
{
}

void ndscan::sendRequests()
{
    sendEchoRequest();
    sendMalformedPacket();

    this_thread::sleep_for(2s);
    _timeout = true;
}

void ndscan::receiveReplies()
{
    static const string filter("ip6 proto 58");
    _pcap->setFilter(filter.c_str());

    auto callback = [=](const struct pcap_pkthdr *header, const u_char *packet) {
        parseReply(header, packet);
    };

    _pcap->setNonBlock(true);

    while(not _timeout) {
        _pcap->dispatch(callback);
    }
}

void ndscan::sendEchoRequest()
{
    // Alocate memory for an echo requests
    const size_t MSG_LEN = ETH_HDR_LEN + IP6_HDR_LEN + ICMP6_ECHO_LEN;
    uint8_t  *msg = new uint8_t[MSG_LEN];
    struct eth_hdr *ethHdr = (struct eth_hdr *) msg;
    struct ip6_hdr *ipHdr = (struct ip6_hdr *) (msg + ETH_HDR_LEN);
    struct icmp6_echo_msg *echoMsg = (struct icmp6_echo_msg *) (msg + ETH_HDR_LEN
                                                        + IP6_HDR_LEN);
    // Set IPv6 header entries
    initIPv6Header(ipHdr);
    inet_pton(AF_INET6, "ff02::1", &ipHdr->ip6_dst);
    ipHdr->ctl.un1.plen = htons(ICMP6_ECHO_LEN);
    ipHdr->ctl.un1.nxt = IPPROTO_ICMPV6;
    ipHdr->ctl.un1.hlim = 255;

    // Set ethernet header entries
    ethHdr->eth_type = htons(ETH_P_IPV6);
    ethMulticastAddr(&ethHdr->eth_dst, &ipHdr->ip6_dst);
    ethHdr->eth_src = *_interInfo.mac.getMAC();

    // Set ICMPv6 message entries
    fillICMPv6Echo(echoMsg, htons(ECHO_ID), 0);

    // Send it from all assigned addresses
    auto addresses = _interInfo.ipv6global;
    addresses.push_back(_interInfo.ipv6local);
    uint32_t ip6checksum;
    for (auto &addr: addresses) {
        ipHdr->ip6_src = *addr.address.getIPv6();

        // ICMPv6 checksum
        ip6checksum = ipv6_hdr_checksum(ipHdr, ICMP6_ECHO_LEN, IPPROTO_ICMPV6);
        icmp6_checksum(ip6checksum, echoMsg, ICMP6_ECHO_LEN);

        _pcap->sendpacket(msg, MSG_LEN);
    }

    delete msg;
}

void ndscan::sendMalformedPacket()
{
    // Alocate memory for an echo requests
    const size_t MSG_LEN = ETH_HDR_LEN + IP6_HDR_LEN + IP6_EXT_DEST_LEN
                            + ICMP6_ECHO_LEN;
    uint8_t  *msg = new uint8_t[MSG_LEN];
    struct eth_hdr *ethHdr = (struct eth_hdr *) msg;
    struct ip6_hdr *ipHdr = (struct ip6_hdr *) (msg + ETH_HDR_LEN);
    struct ip6_ext_dest *ipOpt = (struct ip6_ext_dest *)
            (msg + ETH_HDR_LEN + IP6_HDR_LEN);
    struct icmp6_echo_msg *echoMsg = (struct icmp6_echo_msg *)
            (msg + ETH_HDR_LEN + IP6_HDR_LEN + IP6_EXT_DEST_LEN);

    // Set IPv6 header entries
    initIPv6Header(ipHdr);
    inet_pton(AF_INET6, "ff02::1", &ipHdr->ip6_dst);
    ipHdr->ctl.un1.plen = htons(IP6_EXT_DEST_LEN + ICMP6_ECHO_LEN);
    ipHdr->ctl.un1.nxt = IPPROTO_DSTOPTS;
    ipHdr->ctl.un1.hlim = 255;

    // Set IPv6 dest extension
    ipOpt->nxt = IPPROTO_ICMPV6;
    ipOpt->ext_len = 0;
    ipOpt->opt_type = 128;
    ipOpt->opt_len = 0;
    ipOpt->padding = 0;

    // Set ethernet header entrie
    ethHdr->eth_type = htons(ETH_P_IPV6);
    ethMulticastAddr(&ethHdr->eth_dst, &ipHdr->ip6_dst);
    ethHdr->eth_src = *_interInfo.mac.getMAC();

    // Set ICMPv6 echo msg entries
    fillICMPv6Echo(echoMsg, htons(ECHO_ID), 0);

    auto addresses = _interInfo.ipv6global;
    addresses.push_back(_interInfo.ipv6local);
    uint32_t ip6checksum;
    for (auto &addr: addresses) {
        ipHdr->ip6_src = *addr.address.getIPv6();

        // ICMPv6 checksum
        ip6checksum = ipv6_hdr_checksum(ipHdr, ICMP6_ECHO_LEN, IPPROTO_ICMPV6);
        icmp6_checksum(ip6checksum, echoMsg, ICMP6_ECHO_LEN);

        _pcap->sendpacket(msg, MSG_LEN);
    }

    delete msg;
}

void
ndscan::parseReply(const struct pcap_pkthdr *header, const u_char *packet)
{
    static const size_t MSG_LEN = ETH_HDR_LEN + IP6_HDR_LEN + ICMP6_ECHO_LEN;
    struct eth_hdr *ethHdr = (struct eth_hdr *) packet;
    struct ip6_hdr *ipHdr = (struct ip6_hdr *) (packet + ETH_HDR_LEN);
    struct icmp6_hdr *icmpHdr;
    icmpHdr = (struct icmp6_hdr *) (packet + ETH_HDR_LEN + IP6_HDR_LEN);

    if (icmpHdr->type != 4 && icmpHdr->type != 129)
        return;

    HostAddr host;
    host.net.setAddr(AF_INET6, &ipHdr->ip6_src);
    host.eth.setAddr(AF_PACKET, &ethHdr->eth_src);

    _hosts.push_back(host);
}

}
