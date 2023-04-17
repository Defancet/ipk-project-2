/**
 * IPK Project 2 - ZETA: Network sniffer
 * @author
 *   xkalut00, Maksim Kalutski
 *
 * @file ipk-sniffer.cpp
 * @brief A network analyzer that captures and filters packets on a specific network interface.
 * @date 17.04.2023
 */

#include <iostream>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <string>
#include <ctime>
#include <cctype>
#include <csignal>

#include <pcap.h>

#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <netinet/ip.h>

using namespace std;

pcap_t *handle;

#define EXIT_SUC 0
#define EXIT_ARGS 1
#define EXIT_DEVS 2
#define EXIT_PCAP 3
#define EXIT_FILT 4
#define EXIT_PAC 5
#define EXIT_SIG 6

struct args {
    char *interface;
    size_t numPackets;
    int port;
    int tcp;
    int udp;
    int icmp4;
    int icmp6;
    int arp;
    int ndp;
    int igmp;
    int mld;
};

/**
 * Prints usage of the program.
 */
void printUsage() {
    cout << "Usage:\n"
            "   ./ipk-sniffer [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}\n"
            "\n"
            "Options:\n"
            "   -i|--interface          Set interface device to sniff from.\n"
            "                           If this parameter is not specified a list of active interfaces is printed.\n"
            "   -p port                 Filter packets on the given interface by port.\n"
            "   -n num                  The number of packets to display.\n"
            "   -t|--tcp                Display TCP packets.\n"
            "   -u|--udp                Display UDP packets.\n"
            "   --icmp4                 Display only ICMPv4 packets.\n"
            "   --icmp6                 Display only ICMPv6 echo request/response.\n"
            "   --arp                   Display only ARP frames.\n"
            "   --ndp                   Display only ICMPv6 NDP packets.\n"
            "   --igmp                  Display only IGMP packets.\n"
            "   --mld                   Display only MLD packets." << endl;
}


/**
 * Parses arguments from command line
 * @param args struct to store parsed arguments
 * @param argc number of arguments
 * @param argc array of arguments
 */
bool parseArgs(struct args *args, int argc, char *argv[]) {
    if (argc == 1) {
        return true;
    }

    if (argc == 2) {
        if (strcmp("-i", argv[1]) == 0) {
            return true;
        } else {
            cerr << "ERROR:Invalid argument: " << argv[1] << "." << endl;
            return false;
        }
    }

    for (int i = 1; i < argc; ++i) {
        char *arg = nullptr;
        if (i + 1 < argc) {
            arg = argv[i + 1];
        }

        if (strcmp("-i", argv[i]) == 0 || strcmp("--interface", argv[i]) == 0) {
            if (!arg) {
                cerr << "ERROR:Option " << argv[i] << " requires an argument." << endl;
                return false;
            }
            args->interface = arg;
            ++i;

        } else if (strcmp("-p", argv[i]) == 0) {
            if (!arg) {
                cerr << "ERROR:Option " << argv[i] << " requires an argument." << endl;
                return false;
            }
            char *rest;
            args->port = strtol(arg, &rest, 10);
            if (*rest != '\0' || args->port < 0 || args->port > 65535) {
                cerr << "ERROR:Invalid port number." << endl;
                return false;
            }
            ++i;

        } else if (strcmp("--tcp", argv[i]) == 0) {
            args->tcp = 1;

        } else if (strcmp("--udp", argv[i]) == 0) {
            args->udp = 1;

        } else if (strcmp("--arp", argv[i]) == 0) {
            args->arp = 1;

        } else if (strcmp("--icmp4", argv[i]) == 0) {
            args->icmp4 = 1;

        } else if (strcmp("--icmp6", argv[i]) == 0) {
            args->icmp6 = 1;

        } else if (strcmp("--ndp", argv[i]) == 0) {
            args->ndp = 1;

        } else if (strcmp("--igmp", argv[i]) == 0) {
            args->igmp = 1;

        } else if (strcmp("--mld", argv[i]) == 0) {
            args->mld = 1;

        } else if (strcmp("-n", argv[i]) == 0) {
            if (!arg) {
                cerr << "ERROR:Option " << argv[i] << " requires an argument."<< endl;
                return false;
            }
            char *rest;
            args->numPackets = strtoul(arg, &rest, 10);
            if (*rest != '\0' || args->numPackets <= 0) {
                cerr << "ERROR:Number of packets must be a positive integer." << endl;
                return false;
            }
            ++i;

        } else {
            cerr << "ERROR:Invalid argument: " << argv[i] << "." << endl;
            return false;
        }
    }

    return true;
}

/**
 * Prints list of active interfaces.
 * @param errbuf buffer for error messages
 */
void printActiveInterfaces(char *errbuf) {
    pcap_if_t *allInterfaces;
    if (pcap_findalldevs(&allInterfaces, errbuf) == PCAP_ERROR) {
        cerr << "ERROR:Could not get list of interfaces: " << errbuf << endl;
        exit(EXIT_DEVS);
    }
    if (!allInterfaces) {
        cerr << "ERROR:No active interfaces found." << endl;
        exit(EXIT_DEVS);
    }
    cout << endl;
    for (pcap_if_t *interface = allInterfaces; interface; interface = interface->next) {
        cout << interface->name << endl;
    }
    cout << endl;
    pcap_freealldevs(allInterfaces);
    exit(EXIT_SUC);
}

/**
 * Creates filter string from parsed arguments.
 * @param args struct with parsed arguments
 * @return filter string
 */
string createFilter(struct args *args) {
    string filter;
    string port = to_string(args->port);
    bool orSwitch = false;

    auto appendFilter = [&](const string& s) {
        if (orSwitch) {
            filter.append(" or ");
        }
        filter.append(s);
        orSwitch = true;
    };

    if (args->port >= 0) {
        if (args->udp) appendFilter("(udp and port " + port + ")");
        if (args->tcp) appendFilter("(tcp and port " + port + ")");
    } else {
        if (args->udp) appendFilter("udp");
        if (args->tcp) appendFilter("tcp");
    }

    if (args->arp) appendFilter("arp");
    if (args->icmp4) appendFilter("icmp");
    if (args->igmp) appendFilter("igmp");

    if (args->icmp6) {
        if (args->ndp && args->mld) {
            appendFilter("icmp6");
        } else if (args->ndp && !args->mld) {
            appendFilter("((icmp6 and (icmp6[0] == 128 or icmp6[0] == 129)) or (icmp6 and (icmp6[0] >= 133 and icmp6[0] <= 137)))");
        } else if (!args->ndp && args->mld) {
            appendFilter("((icmp6 and (icmp6[0] == 128 or icmp6[0] == 129)) or (icmp6 and (icmp6[0] >= 130 and icmp6[0] <= 132)))");
        } else {
            appendFilter("(icmp6 and (icmp6[0] == 128 or icmp6[0] == 129))");
        }
    }

    if (args->ndp && args->mld) {
        if (!args->icmp6) {
            appendFilter("(icmp6 and (icmp6[0] >= 130 and icmp6[0] <= 137))");
        }
    }

    if (args->ndp) {
        if (!args->icmp6 && !args->mld) {
            appendFilter("(icmp6 and (icmp6[0] >= 133 and icmp6[0] <= 137))");
        }
    }

    if (args->mld) {
        if (!args->icmp6 && !args->ndp) {
            appendFilter("(icmp6 and (icmp6[0] >= 130 and icmp6[0] <= 132))");
        }
    }

    if (!orSwitch) {
        if (args->port >= 0) {
            filter.append("(udp and port " + port + ") or (tcp and port " + port + ")");
        } else {
            filter.append("tcp or udp");
        }
        filter.append(" or arp or icmp or igmp or icmp6");
    }

    return filter;
}

/**
 * Helper function for the printPacket() function. It is used to parse the time zone offset.
 * @param timestamp timestamp string
 * @param microseconds microseconds
 */
string parseZoneOffset(const char* timestamp, int microseconds) {
    char buffer[40];
    sprintf(buffer, timestamp, microseconds);
    string str(buffer);
    str.insert(str.length() - 2, ":");
    return str;
}

/**
 * Prints and filter the contents of each packet captured by the sniffer.
 * @param header packet header
 * @param packetData packet data
 */
void printPacket(const struct pcap_pkthdr* header, const u_char* packetData) {
    time_t timestamp = header->ts.tv_sec;
    struct tm *localTime = localtime(&timestamp);
    char timestampStr[30];
    strftime(timestampStr, sizeof(timestampStr), "%Y-%m-%dT%H:%M:%S.%%03u%z", localTime);
    cout << "timestamp: " << parseZoneOffset(timestampStr, header->ts.tv_usec / 1000) << endl;

    cout << "src MAC: " << hex << setfill('0');
    for (int i = 0; i < 6; i++) {
        cout << setw(2) << (int)packetData[i];
        if (i < 5) {
            cout << ":";
        }
    }
    cout << dec << endl;

    cout << "dst MAC: " << hex << setfill('0');
    for (int i = 6; i < 12; i++) {
        cout << setw(2) << (int)packetData[i];
        if (i < 11) {
            cout << ":";
        }
    }
    cout << dec << endl;

    u_short etherType = (packetData[12] << 8) | packetData[13];
    const u_char *payload = packetData + 14;
    int payloadSize = header->len - 14;

    cout << "frame length: " << header->len << " bytes" << endl;

    if (etherType == 0x0800) {
        const struct ip *ipHeader = (struct ip *) payload;
        int ipHeaderSize = ipHeader->ip_hl * 4;

        char srcIP[INET6_ADDRSTRLEN], dstIP[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ipHeader->ip_src), srcIP, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), dstIP, INET_ADDRSTRLEN);
        cout << "src IP: " << srcIP << "\n";
        cout << "dst IP: " << dstIP << "\n";

        u_short srcPort = 0, dstPort = 0;
        const u_char *transportPayload = payload + ipHeaderSize;
        if (ipHeader->ip_p == IPPROTO_TCP) {
            const struct tcphdr *tcpHeader = (struct tcphdr *) transportPayload;
            srcPort = ntohs(tcpHeader->th_sport);
            dstPort = ntohs(tcpHeader->th_dport);
        } else if (ipHeader->ip_p == IPPROTO_UDP) {
            const struct udphdr *udpHeader = (struct udphdr *) transportPayload;
            srcPort = ntohs(udpHeader->uh_sport);
            dstPort = ntohs(udpHeader->uh_dport);
        }
        if (srcPort || dstPort) {
            cout << "src port: " << srcPort << "\n";
            cout << "dst port: " << dstPort << "\n";
        }
    }

    cout << endl;

    for (int i = 0; i < header->len; i += 16) {
        cout << "0x" << hex << setw(4) << setfill('0') << i << ": ";

        for (int j = 0; j < 16; j++) {
            if (i + j < header->len) {
                cout << hex << setw(2) << setfill('0') << static_cast<int>(packetData[i + j]) << " ";
            } else {
                cout << "   ";
            }
        }

        for (int j = 0; j < 16; j++) {
            if (i + j < header->len) {
                if (isprint(packetData[i + j])) {
                    cout << packetData[i + j];
                } else {
                    cout << ".";
                }
            } else {
                cout << " ";
            }
            if ((j + 1) % 8 == 0) {
                cout << " ";
            }
        }

        cout << endl;
    }
    cout << endl;
}

/**
 * Function to catch Ctrl-c signal
 */
void signalHandler(int signal) {
    pcap_close(handle);
    cout << endl;
    exit(EXIT_SIG);
}

int main(int argc, char** argv) {
    struct args args = {0};
    args.port = -1;
    args.numPackets = 1;

    if (!parseArgs(&args, argc, argv)) {
        printUsage();
        exit(EXIT_ARGS);
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf) == -1) {
        cerr << "ERROR:Could not initialize pcap: " << errbuf << endl;
        exit(EXIT_PCAP);
    }

    if(!args.interface) {
        printActiveInterfaces(errbuf);
    }

    handle = pcap_create(args.interface, errbuf);
    if (!handle) {
        cerr << "ERROR:Could not create interface " << args.interface << ": " << errbuf << endl;
        exit(EXIT_PCAP);
    }

    pcap_set_snaplen(handle, BUFSIZ);
    pcap_set_promisc(handle, 1);
    pcap_set_timeout(handle, 1000);

    if (pcap_activate(handle) < 0) {
        cerr << "ERROR:Could not activate interface " << args.interface << ": " << pcap_geterr(handle) << endl;
        exit(EXIT_PCAP);
    }

    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;

    if (pcap_lookupnet(args.interface, &net, &mask, errbuf) == -1) {
        cerr << "ERROR:Could not get netmask for interface " << args.interface << ": " << errbuf << endl;
        exit(EXIT_PCAP);
    }

    if (pcap_datalink(handle) != DLT_EN10MB && pcap_datalink(handle) != DLT_LINUX_SLL) {
        cerr << "ERROR:Interface " << args.interface << " is not an Ethernet interface." << endl;
        exit(EXIT_PCAP);
    }

    string filters = createFilter(&args);

    signal(SIGINT, signalHandler);

    if (pcap_compile(handle, &fp, filters.c_str(), 0, net) == PCAP_ERROR) {
        cerr << "ERROR:Could not compile filter: " << pcap_geterr(handle) << endl;
        pcap_close(handle);
        exit(EXIT_FILT);
    }

    if (pcap_setfilter(handle, &fp) == PCAP_ERROR) {
        cerr << "ERROR:Could not set filter: " << pcap_geterr(handle) << endl;
        pcap_close(handle);
        exit(EXIT_FILT);
    }

    pcap_freecode(&fp);

    struct pcap_pkthdr *pktHeader = NULL;
    const u_char *pktData = NULL;
    int res = 0;
    for (int i = 0; i < args.numPackets; ++i) {
        res = pcap_next_ex(handle, &pktHeader, &pktData);
        if (res == 0) {
            cerr << "ERROR:Timeout while waiting for packet." << endl;
            pcap_close(handle);
            exit(EXIT_PAC);
        } else if (res == PCAP_ERROR) {
            cerr << "ERROR:Error while waiting for packet: " << pcap_geterr(handle) << endl;
            pcap_close(handle);
            exit(EXIT_PAC);
        } else if (res == PCAP_ERROR_BREAK) {
            cerr << "ERROR:Loop terminated by pcap_breakloop()." << endl;
            pcap_close(handle);
            exit(EXIT_PAC);
        }
        printPacket(pktHeader, pktData);
    }

    pcap_close(handle);
    exit(EXIT_SUC);
}
