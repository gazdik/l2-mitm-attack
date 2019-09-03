/**
 * @author      Peter Gazdík <xgazdi03(at)stud.fit.vutbr.cz>
 * @date        14/04/2017
 * @copyright   The MIT License (MIT)
 */


#include "addr.h"
#include "netlib.h"

#include <linux/if_packet.h>
#include <netinet/ether.h>

#include <cstring>
#include <map>
#include <stdexcept>
using namespace std;

namespace pds
{

map<int, size_t> ADDR_SIZE
        {
                {AF_INET,   4},
                {AF_INET6,  16},
                {AF_PACKET, 6}
        };

addr::addr(const struct sockaddr *sockaddr)
{
    setAddr(sockaddr);
}

addr::addr() :
        _family{AF_UNSPEC}
{
}

bool addr::isIPv6() const
{
    return _family == AF_INET6;
}

bool addr::isIPv4() const
{
    return _family == AF_INET;
}

size_t addr::size() const
{
    return _size;
}

sa_family_t addr::getFamily() const
{
    return _family;
}

const ip6_addr * addr::getIPv6() const
{
    return &_addr.ipv6;
}

ip4_addr addr::getIPv4() const
{
    return _addr.ipv4;
}

const eth_addr * addr::getMAC() const
{
    return &_addr.mac;
}

void addr::setAddr(const struct sockaddr *sockaddr)
{
    if (sockaddr == nullptr) return;

    _family = sockaddr->sa_family;
    if (_family == AF_INET) {
        _addr.ipv4.data = ((sockaddr_in *) sockaddr)->sin_addr.s_addr;
    }
    else if (_family == AF_INET6) {
        memcpy(&_addr.ipv6, &((sockaddr_in6 *) sockaddr)->sin6_addr,
               IP6_ADDR_LEN);
    }
    else if (_family == AF_PACKET) {
        auto mac_sockaddr = ((sockaddr_ll *) sockaddr);
        memcpy(&_addr.mac, mac_sockaddr->sll_addr, ETH_ADDR_LEN);
    }
}

void addr::operator=(const struct sockaddr *sockaddr)
{
    setAddr(sockaddr);
}

std::string addr::textForm() const
{
    static char buff[256];

    if (_family == AF_UNSPEC) return "";

    if (_family == AF_INET || _family == AF_INET6)
        inet_ntop(_family, &_addr.ipv6, buff, 256);
    else if (_family == AF_PACKET)
        mac_ntop(&_addr.ipv6, buff);

    return buff;
}

void addr::setAddr(sa_family_t family, const void *addr)
{
    _family = family;
    _size = ADDR_SIZE[_family];
    memcpy(&_addr, addr, _size);
}

void addr::setFromString(sa_family_t family, const char *string)
{
    _family = family;
    _size = ADDR_SIZE[_family];

    if (_family == AF_INET || _family == AF_INET6) {
        if (inet_pton(_family, string, &_addr) != 1)
            throw runtime_error("Invalid IPv6 address");
    }
    else if (_family == AF_PACKET) {
        auto mac = ether_aton(string);
        if (mac == nullptr)
            throw runtime_error("Invalid MAC address");
        memcpy(&_addr, mac, _size);
    }
    else
        throw runtime_error("Unsupported address type");
}


} // namespace pdf
