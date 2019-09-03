/**
 * @author      Peter Gazdík <xgazdi03(at)stud.fit.vutbr.cz>
 * @date        16/04/17
 * @copyright   The MIT License (MIT)
 */

#ifndef PDS_HEADERS_H
#define PDS_HEADERS_H

#include <cstdint>
#include <cstddef>

namespace pds
{


/**
 * IPv6 address
 */
static const size_t IP6_ADDR_LEN = 16;

struct ip6_addr
{
    union
    {
        std::uint8_t _8[16];
        std::uint16_t _16[8];
        std::uint32_t _32[4];
    } data;
} __attribute__((__packed__));

/**
 * IPv4 address
 */

static const size_t IP4_ADDR_LEN = 4;

struct ip4_addr
{
    std::uint32_t data;
} __attribute__ ((__packed__));


/**
 * Ethernet address
 */

static const size_t ETH_ADDR_LEN = 6;

struct eth_addr
{
    std::uint8_t octet[ETH_ADDR_LEN];
} __attribute__((__packed__));

/**
 * Ethernet header
 */
struct eth_hdr
{
    struct eth_addr eth_dst;
    struct eth_addr eth_src;
    std::uint16_t eth_type;
} __attribute__((__packed__));

static const size_t ETH_HDR_LEN = sizeof(eth_hdr);

/**
 * ARP header
 */
struct arp_msg
{
	std::uint16_t hrd;	/* Format of hardware address.  */
	std::uint16_t pro;	/* Format of protocol address.  */
	std::uint8_t hln;	/* Length of hardware address.  */
	std::uint8_t pln;	/* Length of protocol address.  */
	std::uint16_t op;	/* ARP opcode (command).   */
	struct eth_addr sha;	/* Sender hardware address */
	struct ip4_addr spa;	/* Sender protocol address */
	struct eth_addr tha;	/* Target hardware address */
	struct ip4_addr tpa;	/* Target protocol address */
} __attribute__((__packed__));

static const size_t ARP_MSG_LEN = sizeof(arp_msg);

/**
 * IPv6 Header
 */
struct ip6_hdr
{
	union
	{
		struct ip6_hdrctl
		{
			std::uint32_t vtf;    /* 4 bits version, 8 bits TC,
 								   * 20 bits flow-ID */
			std::uint16_t plen;   /* payload length */
			std::uint8_t nxt;     /* next header */
			std::uint8_t hlim;    /* hop limit */
		} un1;
		std::uint8_t un2_vt;           /* 4 bits version, top 4 bits tclass */
	} ctl;
	struct ip6_addr ip6_src;      /* source address */
	struct ip6_addr ip6_dst;      /* destination address */
} __attribute__((__packed__));

static const size_t IP6_HDR_LEN = sizeof(ip6_hdr);

/**
 * Destination options header
 */
struct ip6_ext_dest
{
    std::uint8_t nxt;        /* next header */
    std::uint8_t ext_len;        /* length in units of 8 octets */
    std::uint8_t opt_type;
	std::uint8_t opt_len;
    std::uint32_t padding;
} __attribute__((__packed__));

static const size_t IP6_EXT_DEST_LEN = sizeof(ip6_ext_dest);

/**
 * ICMPv6 Header
 */
struct icmp6_hdr
{
	std::uint8_t type;    /* type field */
	std::uint8_t code;    /* code field */
	std::uint16_t cksum;  /* checksum field */
} __attribute__((__packed__));

static const uint8_t ICMP6T_ECHO_REQUEST = 128;
static const uint8_t ICMP6T_ECHO_REPLY = 129;
static const uint8_t ICMP6T_NS = 135;
static const uint8_t ICMP6T_NA = 136;

static const size_t ICMP6_HDR_LEN = sizeof(icmp6_hdr);

/**
 * ICMPv6 Echo Request and Reply Message
 */
struct icmp6_echo_msg
{
    struct icmp6_hdr hdr;
    std::uint16_t id;     /* idendifier */
	std::uint16_t seqn;   /* sequence number */
} __attribute__((__packed__));

static const size_t ICMP6_ECHO_LEN = sizeof(icmp6_echo_msg);

/**
 *	Neighbor Discovery Link-layer Address Option
 */
struct icmp6_eth_opt
{
	std::uint8_t type;
	std::uint8_t len;
	struct eth_addr addr;
} __attribute__((__packed__));

static const size_t ICMP6_ETH_OPT_LEN = sizeof(icmp6_eth_opt);
static const std::uint8_t ICMP6_ETH_OPT_SOURCE = 1;
static const std::uint8_t ICMP6_ETH_OPT_TARGET = 2;
static const std::uint8_t ICMP6_ETH_OPT_OCT_LEN = 1;

/**
 * Neighbor Solicitation Message
 */
struct icmp6_ns_msg
{
	struct icmp6_hdr hdr;
	std::uint32_t rsvd;
} __attribute__((__packed__));


/**
 * Neighbor Advertisement Message
 */
struct icmp6_na_msg
{
    struct icmp6_hdr hdr;
    union
    {
        std::uint8_t rso;
        std::uint32_t rsrvd;
    } body;
	struct ip6_addr targ_ip;
    struct icmp6_eth_opt eth_src;
} __attribute__((__packed__));

static const size_t ICMP6_NA_LEN = sizeof(icmp6_na_msg);
static const uint8_t NDA_R_BIT = 0x80;
static const uint8_t NDA_S_BIT = 0x40;
static const uint8_t NDA_O_BIT = 0x20;

/**
 * Inverse Neighbor Solicitation Message
 */
struct icmp6_ins_msg
{
	struct icmp6_hdr hdr;
	std::uint32_t rsvd;
} __attribute__((__packed__));

/**
 * Inverse Neighbor Advertisement Message
 */
struct icmp6_ina_msg
{
    struct icmp6_hdr hdr;
	std::uint32_t rso;
	struct ip6_addr ip6_addr;
} __attribute__((__packed__));

} // namespace pds



#endif //PDS_HEADERS_H
