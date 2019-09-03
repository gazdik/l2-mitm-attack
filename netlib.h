/**
 * @author      Peter Gazdík <xgazdi03(at)stud.fit.vutbr.cz>
 * @date        14/04/2017
 * @copyright   The MIT License (MIT)
 */

#ifndef PDS_NET_H
#define PDS_NET_H

#include <string>
#include <vector>
#include "addr.h"
#include "headers.h"

namespace pds {

/*
 * Types
 */

struct InterfaceAddr
{
    pds::addr address;
    pds::addr netmask;
};

struct InterfaceInfo
{
    std::string name;
    pds::addr mac;
    InterfaceAddr ipv4;
    InterfaceAddr ipv6local;
    std::vector<InterfaceAddr> ipv6global;
};

/*
 * Functions
 */

InterfaceInfo getInterfaceInfo(const char* interface);

bool isLinkLocal(const struct ip6_addr *addr);

void mac_ntop(const void *mac, char *str);

void initARPRequest(void *buf);
void initARPReply(void *buf);
void initNDAdvertisment(void *buf);

void fillARPRequest(void *buf, const struct eth_addr *sha, const struct ip4_addr *spa,
                    const struct ip4_addr *tpa);

void fillEthHeader(void *buf, const struct eth_addr *dst, const struct eth_addr *src,
                   uint16_t ethType);

void ethMulticastAddr(struct eth_addr *ethAddr, const struct ip6_addr *ip6Addr);

void fillICMPv6Echo(void *buf, uint16_t id, uint16_t seqNumber);

void initIPv6Header(void *addr);

}


#endif //PDS_NET_H
