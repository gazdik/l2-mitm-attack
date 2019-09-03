/**
 * @author      Peter Gazdík <xgazdi03(at)stud.fit.vutbr.cz>
 * @date        17/04/17
 * @copyright   The MIT License (MIT)
 */

#ifndef PDS_SPOOF_H
#define PDS_SPOOF_H

#include "types.h"
#include "addr.h"

namespace pds
{

class spoof
{
public:
    spoof();
    virtual ~spoof();

    virtual void init() = 0;
    virtual void poisoneCache() = 0;
    virtual void stopSpoofing() = 0;

    void setInterface(const char *interface);
    void setVictims(const HostAddr &victim1, const HostAddr &victim2);
    void setInterval(int interval);

protected:
    std::string _interface;
    HostAddr _victim1, _victim2;
    int _interval = 0;
};

}


#endif //PDS_SPOOF_H
