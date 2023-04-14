#include <iostream>
#include <stdlib.h>
#include <string.h>

using namespace std;

#define EXIT_ARG 0
#define EXIT_SUC 1
#define EXIT_PARCE 2
#define EXIT_SIGNAL 3

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
            "   -h|--help               Display the help message\n"
            "   -i|--interface           Set interface device to sniff from.\n"
            "                           If this parameter is not specified a list of active interfaces is printed.\n"
            "   -p port                 Filter packets on the given interface by port.\n"
            "   -t|--tcp                Display TCP packets.\n"
            "   -u|--udp                Display UDP packets.\n"
            "   --icmp4                 Display only ICMPv4 packets.\n"
            "   --icmp6                 Display only ICMPv6 echo request/response).\n"
            "   --arp                   Display only ARP frames.\n"
            "   --ndp                   Display only ICMPv6 NDP packets.\n"
            "   --igmp                  Display only IGMP packets).\n"
            "   --mld                   Display only MLD packets.\n"
            "   -n num                  The number of packets to display." << endl;
}

bool parseArgs(struct args *args, int argc, char *argv[]) {
    if (argc == 1) {
        return true;
    }

    if (argc == 2) {
        if (strcmp("-i", argv[1]) == 0) {
            return true;
        } else {
            cerr << "Invalid argument: " << argv[1] << ".\n";
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
                cerr << "Option " << argv[i] << " requires an argument.\n";
                return false;
            }
            args->interface = arg;
            ++i;

        } else if (strcmp("-p", argv[i]) == 0) {
            if (!arg) {
                cerr << "Option " << argv[i] << " requires an argument.\n";
                return false;
            }
            char *rest;
            args->port = strtol(arg, &rest, 10);
            if (*rest != '\0' || args->port < 0) {
                cerr << "Port must be a positive integer." << endl;
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
                cerr << "Option " << argv[i] << " requires an argument.\n";
                return false;
            }
            char *rest;
            args->numPackets = strtoul(arg, &rest, 10);
            if (*rest != '\0' || args->numPackets <= 0) {
                cerr << "Number of packets must be a positive integer." << endl;
                return false;
            }
            ++i;

        } else {
            cerr << "Invalid argument: " << argv[i] << ".\n";
            return false;
        }
    }

    return true;
}

int main(int argc, char** argv) {
    struct args args;
    memset(&args, 0, sizeof(struct args));
    args.port = -1;
    args.numPackets = 1;
    if (!parseArgs(&args, argc, argv)) {
        printUsage();
        exit(EXIT_ARG);
    }

    if (args.interface) {
        cout << "Interface: " << args.interface << endl;
    } else {
        cout << "No interface specified." << endl;
    }

    if (args.port != -1) {
        cout << "Port: " << args.port << endl;
    } else {
        cout << "No port specified." << endl;
    }

    if (args.tcp) {
        cout << "TCP" << endl;
    }

    if (args.udp) {
        cout << "UDP" << endl;
    }

    if (args.arp) {
        cout << "ARP" << endl;
    }

    if (args.icmp4) {
        cout << "ICMPv4" << endl;
    }

    if (args.icmp6) {
        cout << "ICMPv6" << endl;
    }

    if (args.ndp) {
        cout << "NDP" << endl;
    }

    if (args.igmp) {
        cout << "IGMP" << endl;
    }

    if (args.mld) {
        cout << "MLD" << endl;
    }

    cout << "Number of packets: " << args.numPackets << endl;

    exit(EXIT_SUC);
}
