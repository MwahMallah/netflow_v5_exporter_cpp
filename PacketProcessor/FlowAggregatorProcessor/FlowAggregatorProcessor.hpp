#ifndef FLOW_AGGREGATOR_PROCESSOR_H
#define FLOW_AGGREGATOR_PROCESSOR_H

#include "../../AppInfo/AppInfo.hpp"
#include "../PacketProcessor.hpp"
#include <iostream>
#include <vector>
#include <cstring>
#include <fstream>
#include <cstdint>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/sysinfo.h>

// structure to store Flow information
struct Flow {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t packet_count;
    uint32_t total_bytes;
    uint32_t first_packet;
    uint32_t last_packet;


    Flow(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port)
        : src_ip(src_ip), dst_ip(dst_ip), src_port(src_port), dst_port(dst_port), packet_count(0), total_bytes(0) {
    }
};

class FlowAggregatorProcessor : public PacketProcessor {
private:
    std::vector<Flow> flows; // flow storage
    AppInfo& appInfo;

    // Helper function that finds flow, based on parameters 
    Flow* findFlow(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, long systime) {
        for (auto& flow : flows) {
            bool match = flow.src_ip == src_ip && flow.dst_ip == dst_ip &&
                        flow.src_port == src_port && flow.dst_port == dst_port;

            bool active_expired = (systime - flow.first_packet) > appInfo.active_timeout;
            bool inactive_expired = (systime - flow.last_packet) > appInfo.inactive_timeout;

            // Compare flows by source IP, destination IP, source port and destination port
            if (match && !active_expired && !inactive_expired) {
                return &flow;  // Return existing flow if found
            }
        }
        return nullptr;  // Return nullptr if flow doesn't exist
    }

    // Helper function to get system time in milliseconds
    uint32_t getSystemTime(long ptime) {
        struct sysinfo sys_info;
        sysinfo(&sys_info);
        long sys_uptime = sys_info.uptime * 1000;
        // Get the current time in seconds
        time_t current_time = time(nullptr) * 1000;
        // Convert to milliseconds
        return ptime - current_time + sys_uptime;
    }

public:
    FlowAggregatorProcessor(AppInfo& info) : appInfo(info) {}

    void processPacket(const struct pcap_pkthdr* header, const u_char* data) override {
        // Parse ip header
        auto* ip_header = reinterpret_cast<const struct ip*>(data + 14); //assume ethernet header
        // Parse tcp header
        auto* tcp_header = reinterpret_cast<const struct tcphdr*>(data + 14 + (ip_header->ip_hl * 4));
        auto length = ntohs(ip_header->ip_len);
        auto pcap_time_ms = header->ts.tv_sec * 1000 + header->ts.tv_usec / 1000; 
        long systime = getSystemTime(pcap_time_ms);

        uint32_t src_ip = ip_header->ip_src.s_addr;
        uint32_t dst_ip = ip_header->ip_dst.s_addr;
        uint16_t src_port = tcp_header->th_sport;
        uint16_t dst_port = tcp_header->th_dport;

        // Find or create flow
        Flow* flow = findFlow(src_ip, dst_ip, src_port, dst_port, systime);
        if (!flow) {
            // If flow is not found, create a new one and add to vector
            flows.emplace_back(src_ip, dst_ip, src_port, dst_port);
            flow = &flows.back();
            flow->first_packet = systime;
        }

        // Update flow data
        flow->packet_count++;
        flow->total_bytes += length;  // Increment total bytes by packet length
        flow->last_packet = systime;  // Update the flow end time with each new packet
    }

    // Get all flows
    const std::vector<Flow>& GetFlows() const {
        return flows;
    }
};

#endif
