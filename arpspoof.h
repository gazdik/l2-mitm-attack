/**
 * @author      Peter Gazdík <xgazdi03(at)stud.fit.vutbr.cz>
 * @date        17/04/17
 * @copyright   The MIT License (MIT)
 */

#ifndef PDS_ARPSPOOF_H
#define PDS_ARPSPOOF_H

#include <cstdint>

#include "spoof.h"
#include "pcap.h"
#include "netlib.h"

namespace pds
{

class arpspoof : public spoof
{
public:
    arpspoof();
    virtual ~arpspoof();

    void init() override;
    void poisoneCache() override;
    void stopSpoofing() override;

private:
    void createARPMessages();

private:
    pcap *_pcap = nullptr;
    InterfaceInfo _interInfo;

    std::uint8_t *_victim1msg = nullptr;
    std::uint8_t *_victim2msg = nullptr;
};

}


#endif //PDS_ARPSPOOF_H
