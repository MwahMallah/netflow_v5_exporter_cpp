#ifndef PACKET_PROCESSOR_H
#define PACKET_PROCESSOR_H

#include <pcap.h>

// Interface for packet processing
class PacketProcessor {
public:
    virtual ~PacketProcessor() = default;
    // method for packet processing
    virtual void processPacket(const struct pcap_pkthdr* header, const u_char* data) = 0;
};

#endif
