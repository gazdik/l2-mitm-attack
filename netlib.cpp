/**
 * @author      Peter Gazdík <xgazdi03(at)stud.fit.vutbr.cz>
 * @date        14/04/2017
 * @copyright   The MIT License (MIT)
 */

#include "netlib.h"
#include "headers.h"

#include <ifaddrs.h>
#include <netinet/ether.h>

#include <iostream>
#include <cstring>

using namespace std;

namespace pds
{

InterfaceInfo getInterfaceInfo(const char *interface)
{
    InterfaceInfo info;
    info.name = interface;

    struct ifaddrs *ifaddr;

    if (getifaddrs(&ifaddr) == -1) {
        cerr << "getiffadr error" << endl;
        return info;
    }

    for (struct ifaddrs *ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        // Skip the other interfaces
        if (strcmp(interface, ifa->ifa_name) != 0)
            continue;

        if (ifa->ifa_addr == nullptr) continue;

        auto addrFamily = ifa->ifa_addr->sa_family;

        // Skip the other addresses
        if ((addrFamily != AF_INET6) && (addrFamily != AF_INET)
            && (addrFamily != AF_PACKET))
            continue;


        // Set the mac address
        if (addrFamily == AF_PACKET) {
            info.mac = ifa->ifa_addr;
            continue;
        }

        // Set the IPv4 address and netmask
        if (addrFamily == AF_INET) {
            info.ipv4.address = ifa->ifa_addr;
            info.ipv4.netmask = ifa->ifa_netmask;
        }

        // Set the IPv6 address and netmask
        if (addrFamily == AF_INET6) {
            InterfaceAddr intAddr;

            intAddr.netmask = ifa->ifa_netmask;
            intAddr.address = ifa->ifa_addr;

            auto currAddr = intAddr.address.getIPv6();
            if (isLinkLocal(currAddr)) {
                info.ipv6local = intAddr;
            } else {
                info.ipv6global.push_back(intAddr);
            }

        }
    }

    freeifaddrs(ifaddr);

    return info;
}

void mac_ntop(const void *void_mac, char *str)
{
    const uint8_t *mac = (const uint8_t *) void_mac;
    sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}


void initARPRequest(void *buf)
{
    struct pds::arp_msg *msg = (struct arp_msg *) buf;
    memset(msg, 0, ARP_MSG_LEN);

    msg->hrd = htons(1);
    msg->pro = htons(ETH_P_IP);
    msg->hln = ETH_ADDR_LEN;
    msg->pln = IP4_ADDR_LEN;
    msg->op = htons(1);
}

void initARPReply(void *buf)
{
    struct pds::arp_msg *msg = (struct arp_msg *) buf;
    memset(msg, 0, ARP_MSG_LEN);

    msg->hrd = htons(1);
    msg->pro = htons(ETH_P_IP);
    msg->hln = ETH_ADDR_LEN;
    msg->pln = IP4_ADDR_LEN;
    msg->op = htons(2);
}

void fillARPRequest(void *buf, const struct eth_addr *sha,
                    const struct ip4_addr *spa, const struct ip4_addr *tpa)
{
    struct pds::arp_msg *msg = (struct arp_msg *) buf;
    initARPRequest(buf);

    msg->sha = *sha;
    msg->spa = *spa;
    msg->tpa = *tpa;

    // Target address to zero
//    memcpy(&msg->tha, ether_aton("00:00:00:00:00:00"), ETH_ADDR_LEN);
}

void
fillEthHeader(void *buf, const struct eth_addr *dst, const struct eth_addr *src,
              uint16_t ethType)
{
    struct eth_hdr *header = (struct eth_hdr *) buf;

    header->eth_dst = *dst;
    header->eth_src = *src;
    header->eth_type = ethType;
}

void ethMulticastAddr(struct eth_addr *ethAddr, const struct ip6_addr *ip6Addr)
{
    ethAddr->octet[0] = 0x33;
    ethAddr->octet[1] = 0x33;
    ethAddr->octet[2] = ip6Addr->data._8[12];
    ethAddr->octet[3] = ip6Addr->data._8[13];
    ethAddr->octet[4] = ip6Addr->data._8[14];
    ethAddr->octet[5] = ip6Addr->data._8[15];
}

void fillICMPv6Echo(void *buf, uint16_t id, uint16_t seqNumber)
{
    struct icmp6_echo_msg *echo = (struct icmp6_echo_msg *) buf;

    echo->hdr.type = 128;
    echo->hdr.code = 0;
    echo->hdr.cksum = 0;
    echo->id = id;
    echo->seqn = seqNumber;
}

void initIPv6Header(void *addr)
{
    struct ip6_hdr *hdr = (struct ip6_hdr *) addr;
    memset(hdr, 0, IP6_HDR_LEN);

    hdr->ctl.un2_vt = 6 << 4;
}

bool isLinkLocal(const struct ip6_addr *addr)
{
    return addr->data._8[0] == 0xfe && (addr->data._8[1] & 0xc0) == 0x80;
}

void initNDAdvertisment(void *buf)
{
    struct icmp6_na_msg *msg = (struct icmp6_na_msg *) buf;
    memset(msg, 0, ICMP6_NA_LEN);

    msg->hdr.type = ICMP6T_NA;
    msg->hdr.code = 0;
    msg->eth_src.type = ICMP6_ETH_OPT_TARGET;
    msg->eth_src.len = ICMP6_ETH_OPT_OCT_LEN;
}

//const struct ip6_addr *InterfaceInfo::getLinkLocalAddr()
//{
//    return ipv6local.address.getIPv6();
//}

} // namespace pds
