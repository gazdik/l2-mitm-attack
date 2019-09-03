/**
 * @author      Peter Gazdík <xgazdi03(at)stud.fit.vutbr.cz>
 * @date        15/04/2017
 * @copyright   The MIT License (MIT)
 */

#ifndef PDS_PCAP_H
#define PDS_PCAP_H

#include <cstdlib>
#include <string>
#include <pcap/pcap.h>
#include <functional>

namespace pds
{

class pcap
{
public:
    pcap(const char *interface, int timeout = 100, bool promisc = false);

    ~pcap();

    int sendpacket(const void *buf, size_t size);

    void setFilter(const char *str);
    void dispatch(std::function<void(const struct pcap_pkthdr *,
                                     const u_char *)> callback);
    void breakloop();
    void setNonBlock(bool nonblock);

private:
    void init(int timeout, bool promisc);

    std::string _interface;
    pcap_t *_handle;
    char _errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 _net;
    bpf_u_int32 _mask;

    void processPacket(const struct pcap_pkthdr *pkthdr, const u_char *packet);
    static void staticProcessPacket(u_char *instancePtr,
                                    const struct pcap_pkthdr *pkthdr,
                                    const u_char *packet);

    std::function<void(const struct pcap_pkthdr *, const u_char *)> _callback;

};

} // namespace pds

#endif //PDS_PCAP_H
