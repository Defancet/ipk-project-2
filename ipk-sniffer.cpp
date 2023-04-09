#include <iostream>
#include <string>
#include <getopt.h>

using namespace std;

struct Args {
    string interface;
    int port = -1;
    bool tcp = false;
    bool udp = false;
    bool arp = false;
    bool icmp4 = false;
    bool icmp6 = false;
    bool ndp = false;
    bool igmp = false;
    bool mld = false;
    int num = 1;
};

void printUsage() {
    cout << "Usage:\n"
            "   ./ipk-sniffer [-i interface | --interface interface] {-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}\n"
            "\n"
            "Options:\n"
            "   -h|--help               Display the help message\n"
            "   -i|-interface           Set interface device to sniff from.\n"
            "                           If this parameter is not specified a list of active interfaces is printed.\n"
            "   -p port                 Filter packets on the given interface by port.\n"
            "   -t|--tcp                Display TCP packets.\n"
            "   -u|--udp                Display UDP packets.\n"
            "   --icmp                  Display only ICMPv4 and ICMPv6 packets.\n"
            "   --arp                   Display only ARP frames.\n"
            "   -n num                  The number of packets to display." << endl;
}

Args parseArgs(int argc, char* argv[]) {
    Args args;
    int opt;
    int optIndex;

    const option longOpts[] = {
            {"interface", required_argument, nullptr, 'i'},
            {"tcp", no_argument, nullptr, 't'},
            {"udp", no_argument, nullptr, 'u'},
            {"arp", no_argument, nullptr, 1},
            {"icmp4", no_argument, nullptr, 2},
            {"icmp6", no_argument, nullptr, 3},
            {"ndp", no_argument, nullptr, 4},
            {"igmp", no_argument, nullptr, 5},
            {"mld", no_argument, nullptr, 6},
            {nullptr, 0, nullptr, 0}
    };

    while ((opt = getopt_long(argc, argv, "i:p:tun:", longOpts, &optIndex)) != -1) {
        switch (opt) {
            case 'i':
                args.interface = optarg;
                break;
            case 'p':
                args.port = stoi(optarg);
                break;
            case 't':
                args.tcp = true;
                break;
            case 'u':
                args.udp = true;
                break;
            case 1:
                args.arp = true;
                break;
            case 2:
                args.icmp4 = true;
                break;
            case 3:
                args.icmp6 = true;
                break;
            case 4:
                args.ndp = true;
                break;
            case 5:
                args.igmp = true;
                break;
            case 6:
                args.mld = true;
                break;
            case 'n':
                args.num = stoi(optarg);
                break;
            default:
                printUsage();
                exit(EXIT_FAILURE);
        }
    }

    return args;
}

int main(int argc, char** argv) {
    Args args = parseArgs(argc, argv);

    cout << "Interface: " << args.interface << endl;

    if (args.port != -1) {
        cout << "Port: " << args.port << endl;
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
        cout << "ICMP4" << endl;
    }

    if (args.icmp6) {
        cout << "ICMP6" << endl;
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

    cout << "Num: " << args.num << endl;

    return 0;
}
