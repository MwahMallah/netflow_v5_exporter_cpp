#include <iostream>
#include <vector>
#include "AppInfo/AppInfo.hpp"
#include "PacketProcessor/PacketProcessor.hpp"
#include "PacketProcessor/FlowAggregatorProcessor/FlowAggregatorProcessor.hpp"
#include "PcapReader/PcapReader.hpp"
#include "NetflowSender/NetflowSender.hpp"

int main(int argc, char** argv) 
{
    try {
        AppInfoFactory factory(argc, argv);
        AppInfo info = factory.GetAppInfo();

        FlowAggregatorProcessor aggregator(info);
        PcapReader reader(info.pcap_file, aggregator);

        reader.ProcessPackets();
        auto flows = aggregator.GetFlows();
        NetflowSender sender(info);
        sender.send(flows);
    }
    catch (const std::invalid_argument& ex) {
        std::cerr << "Argument error: " << ex.what() << std::endl;
        return 1; 
    }
    catch(const std::runtime_error& ex) {
        std::cerr << "Runtime error: " << ex.what() << std::endl;
        return 2;
    }

    return 0;
}