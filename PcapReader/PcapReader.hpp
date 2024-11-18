#include "../PacketProcessor/PacketProcessor.hpp"
#include <pcap.h>
#include <stdexcept>
#include <string>

class PcapReader {
private:
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    PacketProcessor& processor; // Reference to current strategy

public:
    PcapReader(const std::string& filePath, PacketProcessor& strategy)
        : handle(nullptr), processor(strategy) {
        handle = pcap_open_offline(filePath.c_str(), errbuf);
        if (!handle) {
            throw std::runtime_error(std::string("Error opening pcap file: ") + errbuf);
        }

        // Apply filter to capture only TCP packets
        struct bpf_program fp;
        const char* filter_exp = "tcp"; // Filter expression for TCP packets
        if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            throw std::runtime_error("Error compiling filter: " + std::string(pcap_geterr(handle)));
        }

        if (pcap_setfilter(handle, &fp) == -1) {
            throw std::runtime_error("Error setting filter: " + std::string(pcap_geterr(handle)));
        }

        pcap_freecode(&fp);  // Free the compiled filter
    }

    // Method for processing packets
    void ProcessPackets() {
        struct pcap_pkthdr* header;
        const u_char* data;
        int res;

        while ((res = pcap_next_ex(handle, &header, &data)) >= 0) {
            processor.processPacket(header, data); // Use current strategy
        }

        if (res == -1) {
            throw std::runtime_error("Error reading packets: " + std::string(pcap_geterr(handle)));
        }
    }

    ~PcapReader() {
        if (handle) {
            pcap_close(handle);
        }
    }
};
