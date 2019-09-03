/**
 * @author      Peter Gazdík <xgazdi03(at)stud.fit.vutbr.cz>
 * @date        16/04/17
 * @copyright   The MIT License (MIT)
 */

#include "checksum.h"

#include <netinet/in.h>

namespace pds
{

using namespace std;

uint32_t net_checksum_sum(uint32_t sum, const void *addr, size_t length)
{
    const uint16_t *word = (const uint16_t *) addr;

    while (length > 1) {
        sum += *word++;
        length -= 2;
    }

    // Add left-over byte, if any
    if (length > 0) {
        sum += *(uint8_t *) word;
    }

    return sum;
}

uint16_t net_checksum_fold(uint32_t sum)
{
    while (sum > 0xffff) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return (uint16_t ) ~sum;
}

uint32_t
ipv6_hdr_checksum(const struct ip6_hdr *hdr, uint16_t plen, uint8_t protocol)
{
    uint32_t pshdr_length = htonl((uint32_t) plen);
    uint32_t pshdr_protocol = htonl(protocol);

    uint32_t sum = 0;
    sum = net_checksum_sum(sum, &hdr->ip6_src, sizeof(hdr->ip6_src));
    sum = net_checksum_sum(sum, &hdr->ip6_dst, sizeof(hdr->ip6_dst));
    sum = net_checksum_sum(sum, &pshdr_length, sizeof(pshdr_length));
    sum = net_checksum_sum(sum, &pshdr_protocol, sizeof(pshdr_protocol));

    return sum;
}

void icmp6_checksum(std::uint32_t ip6_sum, void *icmp6_msg, std::size_t len)
{
    struct icmp6_hdr *hdr = (struct icmp6_hdr *) icmp6_msg;

    // Clear the checksum entry
    hdr->cksum = 0;

    uint32_t sum = net_checksum_sum(ip6_sum, icmp6_msg, len);

    // Use the new checksum value
    hdr->cksum = net_checksum_fold(sum);
}

} // namespace pds
