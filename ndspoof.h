/**
 * @author      Peter Gazdík <xgazdi03(at)stud.fit.vutbr.cz>
 * @date        18/04/17
 * @copyright   The MIT License (MIT)
 */

#ifndef PDS_NDSPOOF_H
#define PDS_NDSPOOF_H

#include <cstdint>

#include "spoof.h"
#include "pcap.h"
#include "netlib.h"

namespace pds
{

class ndspoof : public spoof
{
public:
    ndspoof();
    virtual ~ndspoof();

    void init() override;
    void poisoneCache() override;
    void stopSpoofing() override;

private:
    void createNDMessages();

private:
    pcap *_pcap = nullptr;
    InterfaceInfo _interInfo;

    struct eth_hdr *_ethHdr1, *_ethHdr2;
    struct ip6_hdr *_ipHdr1, *_ipHdr2;
    struct icmp6_na_msg *_ndaMsg1, *_ndaMsg2;
    std::uint8_t  *_victim1msg = nullptr;
    std::uint8_t  *_victim2msg = nullptr;
};

} // namespace pds


#endif //PDS_NDSPOOF_H
