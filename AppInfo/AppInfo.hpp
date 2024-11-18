#ifndef APP_INFO_H
#define APP_INFO_H

#include <string>
#include <stdexcept>
#include <cstring>
#include <cstdlib>

struct AppInfo {
public:
    char* host;
    int port;
    char* pcap_file;
    int active_timeout; //active timeout in ms
    int inactive_timeout; //inactive timeout in ms

    AppInfo() : host(nullptr), port(0), pcap_file(nullptr), 
                active_timeout(60), inactive_timeout(60) {}

    ~AppInfo() {
        delete[] host;
        delete[] pcap_file;
    }
};

class AppInfoFactory {
private:
    int argc;
    char** argv;

    void parseHostAndPort(const std::string& input, AppInfo& info) {
        size_t colon_pos = input.find(':');
        if (colon_pos == std::string::npos) {
            throw std::invalid_argument("Invalid host:port format");
        }

        std::string host = input.substr(0, colon_pos);
        std::string port_str = input.substr(colon_pos + 1);

        info.host = new char[host.size() + 1];
        std::strcpy(info.host, host.c_str());

        info.port = std::stoi(port_str);
        if (info.port <= 0 || info.port > 65535) {
            throw std::invalid_argument("Port number out of range");
        }
    }

public:
    AppInfoFactory(int argc, char** argv) : argc(argc), argv(argv) {}

    AppInfo GetAppInfo() {
        if (argc < 3) {
            throw std::invalid_argument("Not enough arguments");
        }

        AppInfo info;

        // Mandatory arguments
        parseHostAndPort(argv[1], info);

        info.pcap_file = new char[std::strlen(argv[2]) + 1];
        std::strcpy(info.pcap_file, argv[2]);

        // Optional arguments
        for (int i = 3; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "-a" && i + 1 < argc) {
                info.active_timeout = std::stoi(argv[++i]) * 1000;
            } else if (arg == "-i" && i + 1 < argc) {
                info.inactive_timeout = std::stoi(argv[++i]) * 1000;
            } else {
                throw std::invalid_argument("Unknown or invalid argument: " + arg);
            }
        }

        return info;
    }

    ~AppInfoFactory() = default;
};

#endif // APP_INFO_H
