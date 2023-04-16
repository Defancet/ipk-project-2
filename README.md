# IPK Project 2 - ZETA: Network sniffer

        Author:  Maksim Kalutski (xkalut00)
        Date:    2023-04-17

This is a C++ program that implements a network analyzer that captures and filters packets on a specific network
interface. The program is able to display the following protocols: TCP, UDP, ARP, ICMPv4, ICMPv6, NDP, IGMP, and MLD. Packets
can be filtered by port number, protocol and interface. You can also specify the number of packets to display.

## Written in

* [C++20 language](https://en.wikipedia.org/wiki/C%2B%2B)

## Prerequisites
Before using the program, you need to have **g++**, **make** and **libpcap** installed on your **UNIX** operating system.

If you are using **Ubuntu** system you can install `g++` and `make` by running the following command:
```console
$ sudo apt-get install build-essential
```

To install `libpcap` on your system, run the following command:
```console
$ sudo apt install libpcap-dev
```


## Build
To build the program, run the following command:
```console
$ make
```

## Usage
```console
$ sudo ./ipk-sniffer [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}
```

### Command-line arguments
| Argument                  | Description                                                                                                           |
|---------------------------|-----------------------------------------------------------------------------------------------------------------------|
| `-i` <br /> `--interface` | Set interface device to sniff from. <br /> If this parameter is not specified a list of active interfaces is printed. |
| `-p port`                 | Filter packets on the given interface by port.                                                                        |
| `-n num`                  | The number of packets to display.                                                                                     |
| `-t` <br /> `--tcp`       | Display TCP packets.                                                                                                  |
| `-u` <br /> `--udp`       | Display UDP packets.                                                                                                  |
| `--icmp4 `                | Display only ICMPv4 packets.                                                                                          |
| `--icmp6`                 | Display only ICMPv6 echo request/response.                                                                            |
| `--arp`                   | Display only ARP frames.                                                                                              |
| `--ndp`                   | Display only ICMPv6 NDP packets.                                                                                      |
| `--igmp`                  | Display only IGMP packets.                                                                                            |
| `--mld`                   | Display only MLD packets.                                                                                             |


## Usage examples
```console
$ ./ipk-sniffer
```

```console
$ sudo ./ipk-sniffer -i eth0 
```

```console
$ sudo ./ipk-sniffer -i eth0 -p 23 --tcp -n 2
```

```console
$ sudo ./ipk-sniffer -i eth0 -p 22 --tcp --udp --icmp4 --icmp6 --arp --ndp --igmp --mld 
```


## Output examples

```
$ sudo ./ipk-sniffer -i eth0
timestamp: 2021-03-19T18:42:52.362+01:00
src MAC: 00:1c:2e:92:03:80
dst MAC: 00:1b:3f:56:8a:00
frame length: 512 bytes
src IP: 147.229.13.223
dst IP: 10.10.10.56
src port: 4093
dst port: 80

0x0000: 00 19 d1 f7 be e5 00 04 96 1d 34 20 08 00 45 00 ........ ..4 ..
0x0010: 05 a0 52 5b 40 00 36 06 5b db d9 43 16 8c 93 e5 ..R[@.6. [..C....
0x0020: 0d 6d 00 50 0d fb 3d cd 0a ed 41 d1 a4 ff 50 18 .m.P..=. ..A...P.
0x0030: 19 20 c7 cd 00 00 99 17 f1 60 7a bc 1f 97 2e b7 . ...... .`z.....
0x0040: a1 18 f4 0b 5a ff 5f ac 07 71 a8 ac 54 67 3b 39 ....Z._. .q..Tg;9
0x0050: 4e 31 c5 5c 5f b5 37 ed bd 66 ee ea b1 2b 0c 26 N1.\_.7. .f...+.&
0x0060: 98 9d b8 c8 00 80 0c 57 61 87 b0 cd 08 80 00 a1 .......W a.......

```
```
./ipk-sniffer
./ipk-sniffer -i

eth0
any
lo
dummy0
tunl0
sit0
bluetooth-monitor
nflog
nfqueue
dbus-system
dbus-session
bond0

```

## Libraries
The program uses the following libraries:

- `iostream`: for input and output operations.
- `cstdlib`: for functions such as strtol and strtoul.
- `cstring`: for functions such as strcmp.
- `iomanip`: for manipulating input and output formats. -
- `string`: for string handling functions.
- `ctime`: for date and time functions.
- `cctype`: for character classification functions.
- `csignal`: for signal handling.


- `pcap.h`: for packet capture functions.


- `netinet/tcp.h`: for TCP header structure.
- `netinet/udp.h`: for UDP header structure.
- `netinet/in.h`: for internet address structure.
- `netinet/ip.h`: for IP header structure.

## UML Diagram

                              +---------------------------------+
                              |           ipk-sniffer           |
                              +---------------------------------+
                              | - handle: pcap_t*               |
                              +---------------------------------+
                              | - EXIT_SUC: int = 0             |
                              | - EXIT_ARGS: int = 1            |
                              | - EXIT_DEVS: int = 2            |
                              | - EXIT_PCAP: int = 3            |
                              | - EXIT_FILT: int = 4            |
                              | - EXIT_PAC: int = 5             |
                              | - EXIT_SIG: int = 6             |
                              +---------------------------------+
                              | - args: struct                  |
                              |   - interface: char*            |
                              |   - numPackets: size_t          |
                              |   - port: int                   |
                              |   - tcp: int                    |
                              |   - udp: int                    |
                              |   - icmp4: int                  |
                              |   - icmp6: int                  |
                              |   - arp: int                    |
                              |   - ndp: int                    |
                              |   - igmp: int                   |
                              |   - mld: int                    |
                              +---------------------------------+
                              | + printUsage(): void            |
                              | + parseArgs(): bool             |
                              | + printActiveInterfaces(): void |
                              | + createFilter(): string        |
                              | + parseZoneOffset(): string     |
                              | + printPacket(): void           |
                              | + signalHandler(): void         |
                              | + main(): int                   |
                              +---------------------------------+

## Components of the Program
### The program includes the following functions and structures:

1. The `args` struct: This struct is used to store the command line arguments passed to the program. It contains the
   following fields:
    - `interface`: The name of the network interface to sniff from.
    - `port`: The port to filter packets by.
    - `num`: The number of packets to display.
    - `tcp`: A flag indicating whether to display TCP packets.
    - `udp`: A flag indicating whether to display UDP packets.
    - `icmp4`: A flag indicating whether to display ICMPv4 packets.
    - `icmp6`: A flag indicating whether to display ICMPv6 packets.
    - `arp`: A flag indicating whether to display ARP packets.
    - `ndp`: A flag indicating whether to display ICMPv6 NDP packets.
    - `igmp`: A flag indicating whether to display IGMP packets.
    - `mld`: A flag indicating whether to display MLD packets.


2. The `printUsage()` function: This function is responsible for printing out the usage guide for the program.


3. The `parseArgs()` function: This function is responsible for parsing the command line arguments passed to the program
   and storing them in a struct `args`. If an error is encountered (e.g. an invalid option or missing argument), it prints
   an error message to the console and calls the `printUsage()` function.


4. The `printActiveInterfaces()` function: This function uses the `pcap_findalldevs()` function from the `pcap` library
   to get a list of all active network interfaces on the system. It then prints out the name and description of each
   interface to the console. If an error occurs, it prints an error message to the console and exits the program.


5. The `createFilter()` function: This function is responsible for generating a BPF (Berkeley Packet Filter) expression
   based on the user's input. The BPF expression is used to filter packets according to specific criteria, such as source
   or destination IP address, port numbers, and protocol type. The function uses a series of conditional statements to
   build the expression dynamically based on the user's input options.


6. The `parseZoneOffset()` function: This function is a helper function for the `printPacket()` function. It is used to
   parse the time zone offset.


7. The`printPacket()` function: This function is responsible for printing out the contents each packet captured by the
   sniffer.

   First, the function prints out the packet's time stamp in a human-readable format using `ctime()`. Then, it parses the
   Ethernet header and prints the source and destination MAC addresses. If the packet is an ARP packet, it also prints the
   ARP header.

   Next, the function parses the IP header, prints the source and destination IP addresses, and determines the protocol
   used in the packet (TCP, UDP, ICMP, or other). If the protocol is TCP or UDP, it further parses the corresponding
   header and prints the source and destination ports.

   Finally, the function prints the payload of the packet, which is the application-layer data. This is done by iterating
   through the packet data and printing each byte in hex format. If the byte is not printable (i.e., not a character or
   digit), a '.' is printed instead.


8. The `signalHandler()` function: This function is responsible for handling the `SIGINT` signal, which is sent when
   the user presses `CTRL-C` to stop the program.


9. The `main()` function: This function ties everything together. The function starts by parsing the user's input using
   the `parseArgs()` function, and then initializes the pcap library using the `pcap_open_live()` function. The function
   then creates a filter using the `createFilter()` function, and sets up a packet capture loop using the `pcap_loop()`
   function. Inside the packet capture loop, the function calls the `printPacket()` function to print information about
   each packet that matches the filter. The function also sets up a signal handler using the `signal()` function to handle
   `SIGINT` signals. Finally, the program closes the packet capture handle and exits.

## Exit codes
### The program uses the following exit codes:

| Exit code   | Number | Description                                |
|-------------|--------|--------------------------------------------|
| `EXIT_SUC`  | 0      | Successful execution.                      |
| `EXIT_ARGS` | 1      | Incorrect usage of command-line arguments. |
| `EXIT_DEVS` | 2      | Error occurred while listing interfaces.   |
| `EXIT_PCAP` | 3      | Error occurred while initializing pcap.    |
| `EXIT_FILT` | 4      | Error occurred while creating filter.      |
| `EXIT_PAC`  | 5      | Error while processing packet.             |
| `EXIT_SIG`  | 6      | Terminated by a signal.                    | 

## Testing

// TODO

## Bibliography

- [1] [Develop a Packet Sniffer with Libpcap](https://vichargrave.github.io/programming/develop-a-packet-sniffer-with-libpcap/)
- [2] [Programming with Libpcap](http://recursos.aldabaknocking.com/libpcapHakin9LuisMartinGarcia.pdf)
- [3] [PROGRAMMING WITH PCAP](https://www.tcpdump.org/pcap.html)
- [4] [Header Files](https://users.pja.edu.pl/~jms/qnx/help/watcom/clibref/headers.html)
- [5] [Protocol Numbers](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
- [6] [IP address](https://en.wikipedia.org/wiki/IP_address)
- [7] [Transmission Control Protocol](https://cs.wikipedia.org/wiki/Transmission_Control_Protocol)
- [8] [User Datagram Protocol](https://en.wikipedia.org/wiki/User_Datagram_Protocol)
- [9] [Internet Protocol version 4](https://en.wikipedia.org/wiki/IPv4)
- [10] [STD 86 RFC 8200 Internet Protocol, Version 6 (IPv6) Specification](https://www.rfc-editor.org/info/rfc8200)
- [11] [Internet Protocol version 6](https://en.wikipedia.org/wiki/IPv6)
- [12] [RFC 2675 IPv6 Jumbograms](https://www.rfc-editor.org/info/rfc2675)
- [13] [ICMPv6](https://en.wikipedia.org/wiki/ICMPv6)
- [14] [inet_ntop(3) — Linux manual page](https://man7.org/linux/man-pages/man3/inet_ntop.3.html)
- [15] [Address Resolution Protocol](https://en.wikipedia.org/wiki/Address_Resolution_Protocol)
- [16] [Internet Group Management Protocol](https://en.wikipedia.org/wiki/Internet_Group_Management_Protocol)
- [17] [Neighbor Discovery Protocol](https://en.wikipedia.org/wiki/Neighbor_Discovery_Protocol)
- [18] [Multicast Listener Discovery](https://en.wikipedia.org/wiki/Multicast_Listener_Discovery)
- [19] [RFC 3339](https://www.rfc-editor.org/info/rfc3339)