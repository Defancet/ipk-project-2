#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <iomanip>
#include <string>

#include <ctime>
#include <cctype>
#include <cstring>

#include <pcap.h>

#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <netinet/igmp.h>

using namespace std;

#define EXIT_ERR 0
#define EXIT_SUC 1

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
            "   --icmp6                 Display only ICMPv6 echo request/response).\n"
            "   --arp                   Display only ARP frames.\n"
            "   --ndp                   Display only ICMPv6 NDP packets.\n"
            "   --igmp                  Display only IGMP packets).\n"
            "   --mld                   Display only MLD packets." << endl;
}

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

void printActiveInterfaces(char *errbuf) {
    pcap_if_t *allInterfaces;
    if (pcap_findalldevs(&allInterfaces, errbuf) == PCAP_ERROR) {
        cerr << "ERROR:Could not get list of interfaces: " << errbuf << endl;
        exit(EXIT_ERR);
    }
    if (!allInterfaces) {
        cerr << "ERROR:No active interfaces found." << endl;
        exit(EXIT_ERR);
    }
    cout << endl;
    for (pcap_if_t *interface = allInterfaces; interface; interface = interface->next) {
        cout << interface->name << endl;
    }
    cout << endl;
    pcap_freealldevs(allInterfaces);
    exit(EXIT_SUC);
}

int main(int argc, char** argv) {
    struct args args = {0};
    args.port = -1;
    args.numPackets = 1;

    if (!parseArgs(&args, argc, argv)) {
        printUsage();
        exit(EXIT_ERR);
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf) == -1) {
        cerr << "ERROR:Could not initialize pcap: " << errbuf << endl;
        exit(EXIT_ERR);
    }

    if(!args.interface) {
        printActiveInterfaces(errbuf);
    }

    exit(EXIT_SUC);
}
