/**
 * @author      Peter Gazdík <xgazdi03(at)stud.fit.vutbr.cz>
 * @date        16/04/2017
 * @copyright   The MIT License (MIT)
 */

#ifndef PDS_TYPES_H
#define PDS_TYPES_H

#include "addr.h"

namespace pds
{

struct HostAddr
{
    addr eth;
    addr net;
};


} // namespace pds

#endif //PDS_TYPES_H
