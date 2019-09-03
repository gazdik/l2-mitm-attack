/**
 * Author: Peter Gazdík <xgazdi03(at)stud.fit.vutbr.cz>
 * 
 * Date: 15/04/17
 */

#include "pcap.h"

#include <stdexcept>
#include <iostream>
using namespace std;

namespace pds
{

pcap::pcap(const char *interface, int timeout, bool promisc) :
    _interface { interface }
{
    init(timeout, promisc);
}

pcap::~pcap()
{
    pcap_close(_handle);
}

int pcap::sendpacket(const void *buf, size_t size)
{
    return pcap_inject(_handle, buf, size);
}

void pcap::init(int timeout, bool promisc)
{
    _handle = pcap_create(_interface.c_str(), _errbuf);
    pcap_set_promisc(_handle, promisc);
    pcap_set_timeout(_handle, 200);

    if (_handle == nullptr) {
        cerr << "PCAP: Couldn't open device " << _interface
             << ". Try to run the program as root." << endl;
        throw runtime_error("pcap_init");
    }

    if (pcap_activate(_handle) != 0) {
        cerr << "PCAP Activate failed: " << pcap_geterr(_handle) << endl;
        throw runtime_error("pcap_init");
    }

    if (pcap_datalink(_handle) != DLT_EN10MB) {
        cerr << "The device doesn't provide Ethernet headers - not supported"
             << endl;
        throw runtime_error("pcap_init");
    }

    if (pcap_lookupnet(_interface.c_str(), &_net, &_mask, _errbuf)) {
        _net = 0;
        _mask = 0;
    }

}

void pcap::setFilter(const char *filter)
{
    struct bpf_program fp;

    if (pcap_compile(_handle, &fp, filter, true, _net) != 0) {
        cerr << "Couldn't parse filter " << filter << ": "
             << pcap_geterr(_handle) << endl;
        throw runtime_error("pcap_compile");
    }

    if (pcap_setfilter(_handle, &fp) != 0) {
        cerr << "Couldn't set filter " << filter << ": "
             << pcap_geterr(_handle) << endl;
        throw runtime_error("pcap_setfilter");
    }
}

void
pcap::staticProcessPacket(u_char *instancePtr, const struct pcap_pkthdr *pkthdr,
                          const u_char *packet)
{
    pcap *instance = (pcap *) instancePtr;
    instance->processPacket(pkthdr, packet);
}

void pcap::processPacket(const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    if (_callback) {
        _callback(pkthdr, packet);
    }
}

void pcap::dispatch(std::function<void(const struct pcap_pkthdr *,
                                       const u_char *)> callback)
{
    _callback = callback;
    pcap_dispatch(_handle, -1, pcap::staticProcessPacket, (u_char *)this);
}

void pcap::breakloop()
{
    pcap_breakloop(_handle);
}

void pcap::setNonBlock(bool nonblock)
{
    pcap_setnonblock(_handle, nonblock, _errbuf);
}

} // namespace pds