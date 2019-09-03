/**
 * @author      Peter Gazdík <xgazdi03(at)stud.fit.vutbr.cz>
 * @date        16/04/17
 * @copyright   The MIT License (MIT)
 *
 * checksum.h   Checksum calculation according to RFC 1071.
 */

#ifndef PDS_CHECKSUM_H
#define PDS_CHECKSUM_H

#include "headers.h"

#include <cstdint>

namespace pds
{

/**
 * Compute Internet Checksum based on algorithm proposed in RFC 1071.
 * @param sum Previous checksum value (from different memory location) or
 *            0 to start a new checksum.
 * @param addr Location of data.
 * @param length Length of data at address 'addr'
 * @return Checksum value.
 */
uint32_t net_checksum_sum(std::uint32_t sum, const void *addr, size_t length);

/**
 * Fold 32-bit sum to 16-bits. Based on algorithm in RFC 1071.
 * @param total_sum
 * @return
 */
uint16_t net_checksum_fold(std::uint32_t total_sum);

/**
 * Calculate Internet Checksum from the IPv6 header
 * @param hdr IPv6 header
 * @return
 */
/**
 * Calculate Internet Checksum from the IPv6 pseudo header according to
 * RFC 2463, section 8.1
 * @param hdr IPv6 header
 * @param plen Upper-Layer Packet Length in host byte order
 * @param protocol The upper-layer protocol (e.g. 58 for ICMPv6)
 * @return checksum
 */
uint32_t ipv6_hdr_checksum(const struct ip6_hdr *hdr, std::uint16_t plen,
                           std::uint8_t protocol);


/**
 * Calculate checksum of an ICMP6 message of length 'len' and
 * set checksum field in its header.
 * @param ip6_sum
 * @param icmp6_msg
 * @param len
 */
void icmp6_checksum(std::uint32_t ip6_sum, void *icmp6_msg, std::size_t len);

} // namespace pds

#endif //PDS_CHECKSUM_H
