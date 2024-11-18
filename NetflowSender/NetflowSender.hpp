#ifndef NETFLOW_SENDER_H
#define NETFLOW_SENDER_H

#include "../AppInfo/AppInfo.hpp"
#include "../PacketProcessor/FlowAggregatorProcessor/FlowAggregatorProcessor.hpp"
#include <iostream>
#include <vector>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctime>
#include <time.h>
#include <sys/sysinfo.h>

// Structure for NetFlow v5 header
struct NetflowV5Header {
    uint16_t Version;
    uint16_t Count;
    uint32_t SysUptime;
    uint32_t UnixSecs;
    uint32_t UnixNsecs;
    uint32_t FlowSequence;
    uint8_t EngineType;
    uint8_t EngineID;
    uint16_t SamplingInterval;

    // Constructor for NetFlow v5 header initialization
    NetflowV5Header() {
        timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        struct sysinfo sys_info;
        sysinfo(&sys_info);

        Version = htons(5); Count = 0; SysUptime = htonl(sys_info.uptime * 1000); 
        UnixSecs = htonl(ts.tv_sec); UnixNsecs = htonl(ts.tv_nsec); FlowSequence = 0;  
        EngineType = 0; EngineID = 0; SamplingInterval = 0;  
    }
};

// Flow record structure
struct FlowRecord {
    uint32_t IpSrc;
    uint32_t IpDst;
    uint32_t Nexthop;
    uint16_t Input;
    uint16_t Output;
    uint32_t Packets;
    uint32_t Octets;
    uint32_t FpacketSystime;
    uint32_t LpacketSystime;
    uint16_t PortSrc;
    uint16_t PortDst;
    uint8_t Pad1;
    uint8_t TcpFlags;
    uint8_t Prot;
    uint8_t Tos;
    uint16_t SrcAs;
    uint16_t DstAs;
    uint8_t SrcMask;
    uint8_t DstMask;
    uint8_t Pad2[2];

    // Constructor for FlowRecord initialization
    FlowRecord(const Flow& flow) {
        IpSrc = flow.src_ip;
        IpDst = flow.dst_ip;
        Nexthop = 0; Input = 0; Output = 0;               
        Packets = htonl(flow.packet_count); Octets = htonl(flow.total_bytes);   
        FpacketSystime = htonl(flow.first_packet); LpacketSystime = htonl(flow.last_packet);      

        PortSrc = flow.src_port; PortDst = flow.dst_port; 
        Pad1 = 0;                 
        TcpFlags = 0; Prot = 6; Tos = 0; SrcAs = 0; DstAs = 0;               
        SrcMask = 0; DstMask = 0; memset(Pad2, 0, sizeof(Pad2)); 
    }
};

class NetflowSender {
private:
    int sockfd;
    struct sockaddr_in server_addr;
    AppInfo& appInfo;

    // Method for sending flow data to the server
    void sendFlowsToServer(const std::vector<Flow>& flows) {
        // Create NetFlow packet (v5 format)
        uint8_t packet[2048];  // Maximum packet size for NetFlow
        int packet_length = 0;

        // NetFlow v5 header
        NetflowV5Header header;  // Using constructor to initialize header

        // Copy header to packet
        memcpy(packet, &header, sizeof(NetflowV5Header));
        packet_length += sizeof(NetflowV5Header);

        // Process each flow and add it to the packet
        int flow_count = 0;
        for (const auto& flow : flows) {
            // Fill flow_record using constructor
            FlowRecord record(flow);

            // Copy flow_record into packet
            memcpy(packet + packet_length, &record, sizeof(FlowRecord));
            packet_length += sizeof(FlowRecord);

            flow_count++;
        }

        // Update the flow count in the header
        header.Count = htons(flow_count);
        memcpy(packet, &header, sizeof(NetflowV5Header)); // Overwrite header with updated flow count

        // Send packet
        if (sendto(sockfd, packet, packet_length, 0, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            perror("Error sending NetFlow data");
        }
    }

public:
    // Constructor, takes AppInfo to get server data
    NetflowSender(AppInfo& info) : appInfo(info) {
        // Create UDP socket
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0) {
            perror("Error creating socket");
            throw std::runtime_error("Socket creation failed");
        }

        // Set up server address (host and port)
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(appInfo.port);  // Use port from AppInfo
        if (inet_pton(AF_INET, appInfo.host, &server_addr.sin_addr) <= 0) {
            perror("Invalid address or address not supported");
            throw std::runtime_error("Invalid server address");
        }
    }

    // Method for sending NetFlow data
    void send(const std::vector<Flow>& flows) {
        std::vector<Flow> batch; // Holds flows to be sent in one message

        // Loop through all flows and gather them into batches
        for (size_t i = 0; i < flows.size(); ++i) {
            batch.push_back(flows[i]);
            if (batch.size() == 30 || i == flows.size() - 1) {
                sendFlowsToServer(batch);  // Send the batch
                batch.clear();  // Clear the batch for the next group
            }
        }
    }

    // Destructor for closing the socket
    ~NetflowSender() {
        if (sockfd >= 0) {
            close(sockfd);
        }
    }
};

#endif
