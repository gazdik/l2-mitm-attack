/**
 * @author      Peter Gazdík <xgazdi03(at)stud.fit.vutbr.cz>
 * @date        14/04/2017
 * @copyright   The MIT License (MIT)
 */

#ifndef PDS_ADDR_H
#define PDS_ADDR_H

#include <arpa/inet.h>
#include <cstddef>
#include <string>

#include "headers.h"

namespace pds
{

/**
 * Class for storing different types of address
 */
class addr
{
public:
    addr();
    addr(sa_family_t family, const struct ip6_addr *addr);
    addr(sa_family_t family, const struct ip4_addr *addr);
    addr(const struct sockaddr * sockaddr);

    bool isIPv6() const;
    bool isIPv4() const;
    bool isMAC() const;
    std::size_t size() const;

    sa_family_t getFamily() const;
    const struct ip6_addr *getIPv6() const;
    struct ip4_addr getIPv4() const;
    const struct eth_addr *getMAC() const;
    std::string textForm() const;

    void setFromString(sa_family_t family, const char *string);
    void setAddr(sa_family_t family, const void *addr);
    void setAddr(const struct sockaddr *sockaddr);
    void operator = (const struct sockaddr *sockaddr);

private:

    sa_family_t _family;
    union
    {
        struct ip4_addr ipv4;
        struct ip6_addr ipv6;
        struct eth_addr mac;
    } _addr;

    size_t _size = 0;
};

}

#endif // PDS_IPADDR_H
