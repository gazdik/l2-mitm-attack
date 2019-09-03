/**
 * @author      Peter Gazdík <xgazdi03(at)stud.fit.vutbr.cz>
 * @date        17/04/17
 * @copyright   The MIT License (MIT)
 */

#include "spoof.h"

namespace pds {

spoof::spoof()
{
}

spoof::~spoof()
{

}

void spoof::setInterface(const char *interface)
{
    _interface = interface;
}

void spoof::setVictims(const pds::HostAddr &victim1,
                            const pds::HostAddr &victim2)
{
    _victim1 = victim1;
    _victim2 = victim2;
}

void spoof::setInterval(int interval)
{
    _interval = interval;
}

} // namespace pds
