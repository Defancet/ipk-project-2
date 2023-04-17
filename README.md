# IPK Project 2 - ZETA: Network sniffer

        Author:  Maksim Kalutski (xkalut00)
        Date:    2023-04-17

This is a C++ program that implements a network analyzer that captures and filters packets on a specific network
interface. The program is able to display the following protocols: TCP, UDP, ARP, ICMPv4, ICMPv6, NDP, IGMP, and MLD. Packets
can be filtered by port number, protocol and interface. You can also specify the number of packets to display.

## Written in

* [C++20 language](https://en.wikipedia.org/wiki/C%2B%2B)

## Theory

### Transmission Control Protocol (TCP)
A TCP segment consists of a segment header and a data section. The segment header contains 10 mandatory fields, and 
an optional extension field (Options). The TCP header can range in size from 20 to 60 bytes, depending on the size 
of the options field. Some of the fields in the TCP header include source port number, destination port number, 
sequence number, acknowledgement number and checksum.

                                  0                   1                   2                   3
                                  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                 |          Source Port          |       Destination Port        |
                                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                 |                        Sequence Number                        |
                                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                 |                    Acknowledgment Number                      |
                                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                 |  Data |       |C|E|U|A|P|R|S|F|                               |
                                 | Offset| Rsrvd |W|C|R|C|S|S|Y|I|            Window             |
                                 |       |       |R|E|G|K|H|T|N|N|                               |
                                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                 |           Checksum            |         Urgent Pointer        |
                                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                 |                           [Options]                           |
                                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                 |                                                               :
                                 :                             Data                              :
                                 :                                                               |
                                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


### User Datagram Protocol (UDP)
UDP segment consists of an 8-byte header and variable length data1. The first four bytes of the UDP header store the
port numbers for the source and destination. The next two bytes store the length (in bytes) of the segment (including 
the header). The final two bytes of the UDP header is the checksum, a field that’s used by the sender and receiver t
o check for data corruption.

                                             0      7 8     15 16    23 24    31
                                            +--------+--------+--------+--------+
                                            |     Source      |   Destination   |
                                            |      Port       |      Port       |
                                            +--------+--------+--------+--------+
                                            |                 |                 |
                                            |     Length      |    Checksum     |
                                            +--------+--------+--------+--------+
                                            |
                                            |          data octets ...
                                            +---------------- ...

### Address Resolution Protocol (ARP)
ARP is a communication protocol used for discovering the link layer address, such as a MAC address, associated with a 
given internet layer address, typically an IPv4 address. The ARP packet size is 28 bytes and contains fields such as 
Hardware type (HTYPE), Protocol type (PTYPE), Hardware address length (HLEN), Protocol address length (PLEN), Operation 
(OPER), Sender hardware address (SHA), Sender protocol address (SPA), Target hardware address (THA) and Target protocol 
address (TPA).
                              
                                            0        7        15       23       31
                                            +--------+--------+--------+--------+
                                            |       HT        |        PT       |
                                            +--------+--------+--------+--------+
                                            |  HAL   |  PAL   |        OP       |
                                            +--------+--------+--------+--------+
                                            |         S_HA (bytes 0-3)          |
                                            +--------+--------+--------+--------+
                                            | S_HA (bytes 4-5)|S_L32 (bytes 0-1)|
                                            +--------+--------+--------+--------+
                                            |S_L32 (bytes 2-3)|S_NID (bytes 0-1)|
                                            +--------+--------+--------+--------+
                                            |         S_NID (bytes 2-5)         |
                                            +--------+--------+--------+--------+
                                            |S_NID (bytes 6-7)| T_HA (bytes 0-1)|
                                            +--------+--------+--------+--------+
                                            |         T_HA (bytes 3-5)          |
                                            +--------+--------+--------+--------+
                                            |         T_L32 (bytes 0-3)         |
                                            +--------+--------+--------+--------+
                                            |         T_NID (bytes 0-3)         |
                                            +--------+--------+--------+--------+
                                            |         T_NID (bytes 4-7)         |
                                            +--------+--------+--------+--------+

### Internet Control Message Protocol
ICMP is a supporting protocol in the Internet protocol suite used by network devices to send error messages and 
operational information indicating success or failure when communicating with another IP address. All ICMP packets have 
an 8-byte header and variable-sized data section. The first 4 bytes of the header have fixed format, while the last 
4 bytes depend on the type/code of that ICMP packet.

                               0                   1                   2                   3
                               0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                              |     Type      |     Code      |           unused              |
                              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                              |      Internet Header + 64 bits of Original Data Datagram      |
                              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

### Internet Group Management Protocol
IGMP is a protocol that allows several devices to share one IP address so they can all receive the same data.
IGMP is a network layer protocol used to set up multicasting on networks that use the Internet Protocol version 4 
(IPv4). IGMP messages have an 8-byte header and variable-sized data section.

                               0                   1                   2                   3
                               0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                              |  Type = 0x11  | Max Resp Code |           Checksum            |
                              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                              |                         Group Address                         |
                              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                              | Resv  |S| QRV |     QQIC      |     Number of Sources (N)     |
                              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                              |                       Source Address [1]                      |
                              +-                                                             -+
                              |                       Source Address [2]                      |
                              +-                              .                              -+
                              .                               .                               .
                              .                               .                               .
                              +-                                                             -+
                              |                       Source Address [N]                      |
                              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


### Internet Control Message Protocol (ICMPv6)
ICMPv6 is an integral part of IPv6 and performs error reporting and diagnostic functions. ICMPv6 has a framework for 
extensions to implement new features. Several extensions have been published, defining new ICMPv6 message types as well 
as new options for existing ICMPv6 message types. Neighbor Discovery Protocol (NDP) is a node discovery protocol based 
on ICMPv6 which replaces and enhances functions of ARP1. Multicast Listener Discovery (MLD) is used by IPv6 routers 
for discovering multicast listeners on a directly attached link, much like Internet Group Management Protocol (IGMP) 
is used in IPv41.

                               0                   1                   2                   3
                               0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                              |     Type      |     Code      |          Checksum             |
                              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                              |                                                               |
                              +                         Message Body                          +
                              |                                                               |


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

# **Testing**

The program has been tested on the **[Windows Subsystem for Linux 2 (WSL2)](https://en.wikipedia.org/wiki/Windows_Subsystem_for_Linux)** 
running **Ubuntu 22.04.1 LTS** and on **NixOS 22.11**. I used the **Wireshark** program to capture packets on the same network interface
that the sniffer was sniffing from. I then compared the output of the sniffer with the output of Wireshark to make sure
that the sniffer was working correctly. 

For sending packets, I used python scripts that located in the `tests\skripts` directory. Each script sends a 
different type of packet (ARP, ICMPv6, IGMP, MLD, and NDP). To run each script, navigate to the directory containing the
scripts open terminal here, and run the script using the `sudo python3.10 tests/skripts/<name>.py` command. You also need to have
the `scapy` library installed on your system. To install the library, run the `pip install scapy` command.

The author of these scripts is **Dias Assatulla** (_xassat00@stud.fit.vutbr.cz_), to whom I am extremely grateful for
his valuable assistance.

I also used the `telnet`, `ping` and `nping` commands to send packets. To use the `nping` command, you need to have
the `nmap` library installed on your system. To install the library, run the `sudo apt install nmap` command.

### To run the tests:

Clone the repository, navigate to the cloned directory, open another terminal there, and compile the program using the `make` 
command. Once compilation is complete, run the program by executing the `./ipk-sniffer` command with the command-line
arguments. 

We will need to use two terminals for this. In the first terminal, we will run the sniffer, and in the second
terminal, we will be sending packets.

## Section 1: Interface listing

### Test 1: Interface not specified:

#### Expected output:
List of active interfaces

#### Actual output:
```console
$ ./ipk-sniffer

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


### Test 2: Interface without a value:

#### Expected output:
List of active interfaces

#### Actual output:
```console
$ ./ipk-sniffer -i

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

## Section 2: Filtering packets by protocol type

### Test 3: Sniffing only **ICMPv4** packets from the `eth0` interface:
#### Input:
```console
$ ping google.com
PING google.com (142.251.36.142) 56(84) bytes of data.
64 bytes from prg03s12-in-f14.1e100.net (142.251.36.142): icmp_seq=1 ttl=116 time=19.2 ms
^C
--- google.com ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 19.215/19.215/19.215/0.000 ms
```

#### Expected output:
```console
Frame 459: 98 bytes on wire (784 bits), 98 bytes captured (784 bits) on interface eth0, id 0
    Section number: 1
    Interface id: 0 (eth0)
    Encapsulation type: Ethernet (1)
    Arrival Time: Apr 17, 2023 16:12:45.471123442 CEST
    [Time shift for this packet: 0.000000000 seconds]
    Epoch Time: 1681740765.471123442 seconds
    [Time delta from previous captured frame: 0.000392126 seconds]
    [Time delta from previous displayed frame: 0.000392126 seconds]
    [Time since reference or first frame: 2521.996453020 seconds]
    Frame Number: 459
    Frame Length: 98 bytes (784 bits)
    Capture Length: 98 bytes (784 bits)
    [Frame is marked: False]
    [Frame is ignored: False]
    [Protocols in frame: eth:ethertype:ip:icmp:data]
    [Coloring Rule Name: ICMP]
    [Coloring Rule String: icmp || icmpv6]
Ethernet II, Src: Microsof_0c:c9:5c (00:15:5d:0c:c9:5c), Dst: Microsof_00:c4:e1 (00:15:5d:00:c4:e1)
Internet Protocol Version 4, Src: 172.18.216.210, Dst: 142.251.36.142
Internet Control Message Protocol

0000   00 15 5d 00 c4 e1 00 15 5d 0c c9 5c 08 00 45 00   ..].....]..\..E.
0010   00 54 1a 1c 40 00 40 01 e8 1e ac 12 d8 d2 8e fb   .T..@.@.........
0020   24 8e 08 00 0f 5a be e9 00 01 dd 53 3d 64 00 00   $....Z.....S=d..
0030   00 00 49 30 07 00 00 00 00 00 10 11 12 13 14 15   ..I0............
0040   16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25   .......... !"#$%
0050   26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35   &'()*+,-./012345
0060   36 37                                             67
```
#### Actual output:
```console
$ sudo ./ipk-sniffer -i eth0 --icmp4
timestamp: 2023-04-17T16:12:45.471+02:00
src MAC: 00:15:5d:00:c4:e1
dst MAC: 00:15:5d:0c:c9:5c
frame length: 98 bytes
src IP: 172.18.216.210
dst IP: 142.251.36.142

0x0000: 00 15 5d 00 c4 e1 00 15 5d 0c c9 5c 08 00 45 00 ..]..... ]..\..E.
0x0010: 00 54 1a 1c 40 00 40 01 e8 1e ac 12 d8 d2 8e fb .T..@.@. ........
0x0020: 24 8e 08 00 0f 5a be e9 00 01 dd 53 3d 64 00 00 $....Z.. ...S=d..
0x0030: 00 00 49 30 07 00 00 00 00 00 10 11 12 13 14 15 ..I0.... ........
0x0040: 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 ........ .. !"#$%
0x0050: 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 &'()*+,- ./012345
0x0060: 36 37                                           67

```

### Test 4: Sniffing only **ICMPv6** packets from the `eth0` interface:
#### Input:
```console
$ sudo python3.10 tests/skripts/icmpv6.py
.
Sent 1 packets.
```

#### Expected output:
```console
Frame 2: 73 bytes on wire (584 bits), 73 bytes captured (584 bits) on interface eth0, id 0
    Section number: 1
    Interface id: 0 (eth0)
    Encapsulation type: Ethernet (1)
    Arrival Time: Apr 17, 2023 16:18:28.536361338 CEST
    [Time shift for this packet: 0.000000000 seconds]
    Epoch Time: 1681741108.536361338 seconds
    [Time delta from previous captured frame: 1.044950546 seconds]
    [Time delta from previous displayed frame: 1.044950546 seconds]
    [Time since reference or first frame: 1.044950546 seconds]
    Frame Number: 2
    Frame Length: 73 bytes (584 bits)
    Capture Length: 73 bytes (584 bits)
    [Frame is marked: False]
    [Frame is ignored: False]
    [Protocols in frame: eth:ethertype:ipv6:icmpv6:data]
    [Coloring Rule Name: ICMP]
    [Coloring Rule String: icmp || icmpv6]
Ethernet II, Src: Microsof_0c:c9:5c (00:15:5d:0c:c9:5c), Dst: Broadcast (ff:ff:ff:ff:ff:ff)
Internet Protocol Version 6, Src: fe80::90ce:1827:6881:68fd, Dst: fe80::90ce:1827:6881:6899
Internet Control Message Protocol v6

0000   ff ff ff ff ff ff 00 15 5d 0c c9 5c 86 dd 60 00   ........]..\..`.
0010   00 00 00 13 3a 40 fe 80 00 00 00 00 00 00 90 ce   ....:@..........
0020   18 27 68 81 68 fd fe 80 00 00 00 00 00 00 90 ce   .'h.h...........
0030   18 27 68 81 68 99 80 00 26 aa 08 ae 0d 05 48 65   .'h.h...&.....He
0040   6c 6c 6f 20 57 6f 72 6c 64                        llo World
```

#### Actual output:
```console
$ sudo ./ipk-sniffer -i eth0 --icmp6
timestamp: 2023-04-17T16:18:28.536+02:00
src MAC: ff:ff:ff:ff:ff:ff
dst MAC: 00:15:5d:0c:c9:5c
frame length: 73 bytes

0x0000: ff ff ff ff ff ff 00 15 5d 0c c9 5c 86 dd 60 00 ........ ]..\..`.
0x0010: 00 00 00 13 3a 40 fe 80 00 00 00 00 00 00 90 ce ....:@.. ........
0x0020: 18 27 68 81 68 fd fe 80 00 00 00 00 00 00 90 ce .'h.h... ........
0x0030: 18 27 68 81 68 99 80 00 26 aa 08 ae 0d 05 48 65 .'h.h... &.....He
0x0040: 6c 6c 6f 20 57 6f 72 6c 64                      llo Worl d

```

### Test 5: Sniffing only **ARP** packets from the `eth0` interface:

#### Input:
```console
$ sudo python3.10 tests/skripts/arp.py
.
Sent 1 packets.
```

#### Expected output:
```console
Frame 54: 42 bytes on wire (336 bits), 42 bytes captured (336 bits) on interface eth0, id 0
    Section number: 1
    Interface id: 0 (eth0)
    Encapsulation type: Ethernet (1)
    Arrival Time: Apr 17, 2023 16:22:56.391129817 CEST
    [Time shift for this packet: 0.000000000 seconds]
    Epoch Time: 1681741376.391129817 seconds
    [Time delta from previous captured frame: 2.492000909 seconds]
    [Time delta from previous displayed frame: 2.492000909 seconds]
    [Time since reference or first frame: 268.899719025 seconds]
    Frame Number: 54
    Frame Length: 42 bytes (336 bits)
    Capture Length: 42 bytes (336 bits)
    [Frame is marked: False]
    [Frame is ignored: False]
    [Protocols in frame: eth:ethertype:arp]
    [Coloring Rule Name: ARP]
    [Coloring Rule String: arp]
Ethernet II, Src: Microsof_0c:c9:5c (00:15:5d:0c:c9:5c), Dst: Broadcast (ff:ff:ff:ff:ff:ff)
Address Resolution Protocol (request)

0000   ff ff ff ff ff ff 00 15 5d 0c c9 5c 08 06 00 01   ........]..\....
0010   08 00 06 04 00 01 ff ff ff ff ff ff c0 a8 01 01   ................
0020   00 00 00 00 00 00 c0 a8 01 02                     ..........
```

#### Actual output:
```console
$ sudo ./ipk-sniffer -i eth0 --arp
timestamp: 2023-04-17T16:22:56.391+02:00
src MAC: ff:ff:ff:ff:ff:ff
dst MAC: 00:15:5d:0c:c9:5c
frame length: 42 bytes

0x0000: ff ff ff ff ff ff 00 15 5d 0c c9 5c 08 06 00 01 ........ ]..\....
0x0010: 08 00 06 04 00 01 ff ff ff ff ff ff c0 a8 01 01 ........ ........
0x0020: 00 00 00 00 00 00 c0 a8 01 02                   ........ ..

```

### Test 6: Sniffing only **IGMPv2** packets from the `eth0` interface:

#### Input:
```console
$ sudo python3.10 tests/skripts/igmp.py 
.
Sent 1 packets.
```

#### Expected output:
```console
Frame 80: 42 bytes on wire (336 bits), 42 bytes captured (336 bits) on interface eth0, id 0
    Section number: 1
    Interface id: 0 (eth0)
    Encapsulation type: Ethernet (1)
    Arrival Time: Apr 17, 2023 16:26:28.451445433 CEST
    [Time shift for this packet: 0.000000000 seconds]
    Epoch Time: 1681741588.451445433 seconds
    [Time delta from previous captured frame: 3.474157215 seconds]
    [Time delta from previous displayed frame: 3.474157215 seconds]
    [Time since reference or first frame: 480.960034641 seconds]
    Frame Number: 80
    Frame Length: 42 bytes (336 bits)
    Capture Length: 42 bytes (336 bits)
    [Frame is marked: False]
    [Frame is ignored: False]
    [Protocols in frame: eth:ethertype:ip:igmp:igmp]
    [Coloring Rule Name: Routing]
    [Coloring Rule String: hsrp || eigrp || ospf || bgp || cdp || vrrp || carp || gvrp || igmp || ismp]
Ethernet II, Src: Microsof_0c:c9:5c (00:15:5d:0c:c9:5c), Dst: IPv4mcast_01 (01:00:5e:00:00:01)
Internet Protocol Version 4, Src: 172.18.216.210, Dst: 224.0.0.1
Internet Group Management Protocol

0000   01 00 5e 00 00 01 00 15 5d 0c c9 5c 08 00 45 00   ..^.....]..\..E.
0010   00 1c 00 01 00 00 01 02 54 f9 ac 12 d8 d2 e0 00   ........T.......
0020   00 01 11 14 ee eb 00 00 00 00                     ..........
```

#### Actual output:
```console
$ sudo ./ipk-sniffer -i eth0 --igmp
timestamp: 2023-04-17T16:26:28.451+02:00
src MAC: 01:00:5e:00:00:01
dst MAC: 00:15:5d:0c:c9:5c
frame length: 42 bytes
src IP: 172.18.216.210
dst IP: 224.0.0.1

0x0000: 01 00 5e 00 00 01 00 15 5d 0c c9 5c 08 00 45 00 ..^..... ]..\..E.
0x0010: 00 1c 00 01 00 00 01 02 54 f9 ac 12 d8 d2 e0 00 ........ T.......
0x0020: 00 01 11 14 ee eb 00 00 00 00                   ........ ..

```


### Test 7: Sniffing only **MLD** packets from the `eth0` interface:

#### Input:
```console
$ sudo python3.10 tests/skripts/mld.py
.
Sent 1 packets.
```

#### Expected output:
```console
Frame 130: 78 bytes on wire (624 bits), 78 bytes captured (624 bits) on interface eth0, id 0
    Section number: 1
    Interface id: 0 (eth0)
    Encapsulation type: Ethernet (1)
    Arrival Time: Apr 17, 2023 16:32:11.731386639 CEST
    [Time shift for this packet: 0.000000000 seconds]
    Epoch Time: 1681741931.731386639 seconds
    [Time delta from previous captured frame: 29.414091852 seconds]
    [Time delta from previous displayed frame: 29.414091852 seconds]
    [Time since reference or first frame: 824.239975847 seconds]
    Frame Number: 130
    Frame Length: 78 bytes (624 bits)
    Capture Length: 78 bytes (624 bits)
    [Frame is marked: False]
    [Frame is ignored: False]
    [Protocols in frame: eth:ethertype:ipv6:icmpv6]
    [Coloring Rule Name: ICMP]
    [Coloring Rule String: icmp || icmpv6]
Ethernet II, Src: Microsof_0c:c9:5c (00:15:5d:0c:c9:5c), Dst: IPv6mcast_16 (33:33:00:00:00:16)
Internet Protocol Version 6, Src: fe80::215:5dff:fe0c:c95c, Dst: ff02::16
Internet Control Message Protocol v6

0000   33 33 00 00 00 16 00 15 5d 0c c9 5c 86 dd 60 00   33......]..\..`.
0010   00 00 00 18 3a 01 fe 80 00 00 00 00 00 00 02 15   ....:...........
0020   5d ff fe 0c c9 5c ff 02 00 00 00 00 00 00 00 00   ]....\..........
0030   00 00 00 00 00 16 82 00 32 7f 27 10 00 00 ff 02   ........2.'.....
0040   00 00 00 00 00 00 00 00 00 00 00 01 00 02         ..............
```

#### Actual output:
```console
sudo ./ipk-sniffer -i eth0 --mld
timestamp: 2023-04-17T16:32:11.731+02:00
src MAC: 33:33:00:00:00:16
dst MAC: 00:15:5d:0c:c9:5c
frame length: 78 bytes

0x0000: 33 33 00 00 00 16 00 15 5d 0c c9 5c 86 dd 60 00 33...... ]..\..`.
0x0010: 00 00 00 18 3a 01 fe 80 00 00 00 00 00 00 02 15 ....:... ........
0x0020: 5d ff fe 0c c9 5c ff 02 00 00 00 00 00 00 00 00 ]....\.. ........
0x0030: 00 00 00 00 00 16 82 00 32 7f 27 10 00 00 ff 02 ........ 2.'.....
0x0040: 00 00 00 00 00 00 00 00 00 00 00 01 00 02       ........ ......


```


### Test 8: Sniffing only **NDP** packets from the `eth0` interface:

#### Input:
```console
$ sudo python3.10 tests/skripts/ndp.py 
.
Sent 1 packets.
```

#### Expected output:
```console
Frame 161: 86 bytes on wire (688 bits), 86 bytes captured (688 bits) on interface eth0, id 0
    Section number: 1
    Interface id: 0 (eth0)
    Encapsulation type: Ethernet (1)
    Arrival Time: Apr 17, 2023 16:35:17.011113066 CEST
    [Time shift for this packet: 0.000000000 seconds]
    Epoch Time: 1681742117.011113066 seconds
    [Time delta from previous captured frame: 4.648404326 seconds]
    [Time delta from previous displayed frame: 4.648404326 seconds]
    [Time since reference or first frame: 1009.519702274 seconds]
    Frame Number: 161
    Frame Length: 86 bytes (688 bits)
    Capture Length: 86 bytes (688 bits)
    [Frame is marked: False]
    [Frame is ignored: False]
    [Protocols in frame: eth:ethertype:ipv6:icmpv6]
    [Coloring Rule Name: ICMP]
    [Coloring Rule String: icmp || icmpv6]
Ethernet II, Src: Microsof_0c:c9:5c (00:15:5d:0c:c9:5c), Dst: IPv6mcast_ff:00:12:34 (33:33:ff:00:12:34)
Internet Protocol Version 6, Src: fe80::215:5dff:fe0c:c95c, Dst: ff02::1:ff00:1234
Internet Control Message Protocol v6

0000   33 33 ff 00 12 34 00 15 5d 0c c9 5c 86 dd 60 00   33...4..]..\..`.
0010   00 00 00 20 3a ff fe 80 00 00 00 00 00 00 02 15   ... :...........
0020   5d ff fe 0c c9 5c ff 02 00 00 00 00 00 00 00 00   ]....\..........
0030   00 01 ff 00 12 34 87 00 0a 39 00 00 00 00 fe 80   .....4...9......
0040   00 00 00 00 00 00 00 00 00 00 00 00 12 34 01 01   .............4..
0050   00 15 5d 0c c9 5c                                 ..]..\
```

#### Actual output:
```console
$ sudo ./ipk-sniffer -i eth0 --ndp
timestamp: 2023-04-17T16:35:17.011+02:00
src MAC: 33:33:ff:00:12:34
dst MAC: 00:15:5d:0c:c9:5c
frame length: 86 bytes

0x0000: 33 33 ff 00 12 34 00 15 5d 0c c9 5c 86 dd 60 00 33...4.. ]..\..`.
0x0010: 00 00 00 20 3a ff fe 80 00 00 00 00 00 00 02 15 ... :... ........
0x0020: 5d ff fe 0c c9 5c ff 02 00 00 00 00 00 00 00 00 ]....\.. ........
0x0030: 00 01 ff 00 12 34 87 00 0a 39 00 00 00 00 fe 80 .....4.. .9......
0x0040: 00 00 00 00 00 00 00 00 00 00 00 00 12 34 01 01 ........ .....4..
0x0050: 00 15 5d 0c c9 5c                               ..]..\

```

## Section 3: Filtering packets by **TCP** or **UDP** protocol

### Test 9: Sniffing only **TCP** packets from the `eth0` interface:

#### Input:
```console
$ sudo nping --tcp google.com

Starting Nping 0.7.80 ( https://nmap.org/nping ) at 2023-04-17 16:38 CEST
SENT (0.0513s) TCP 172.18.216.210:47351 > 142.251.36.142:80 S ttl=64 id=21657 iplen=40  seq=3872778998 win=1480 
RCVD (0.0703s) TCP 142.251.36.142:80 > 172.18.216.210:47351 SA ttl=119 id=0 iplen=44  seq=1715459389 win=65535 <mss 1412>
^C 
Max rtt: 19.000ms | Min rtt: 19.000ms | Avg rtt: 19.000ms
Raw packets sent: 1 (40B) | Rcvd: 1 (44B) | Lost: 0 (0.00%)
Nping done: 1 IP address pinged in 0.45 seconds
```

#### Expected output:
```console
Frame 202: 54 bytes on wire (432 bits), 54 bytes captured (432 bits) on interface eth0, id 0
    Section number: 1
    Interface id: 0 (eth0)
    Encapsulation type: Ethernet (1)
    Arrival Time: Apr 17, 2023 16:38:33.732130737 CEST
    [Time shift for this packet: 0.000000000 seconds]
    Epoch Time: 1681742313.732130737 seconds
    [Time delta from previous captured frame: 0.049441534 seconds]
    [Time delta from previous displayed frame: 0.049441534 seconds]
    [Time since reference or first frame: 1206.240719945 seconds]
    Frame Number: 202
    Frame Length: 54 bytes (432 bits)
    Capture Length: 54 bytes (432 bits)
    [Frame is marked: False]
    [Frame is ignored: False]
    [Protocols in frame: eth:ethertype:ip:tcp]
    [Coloring Rule Name: HTTP]
    [Coloring Rule String: http || tcp.port == 80 || http2]
Ethernet II, Src: Microsof_0c:c9:5c (00:15:5d:0c:c9:5c), Dst: Microsof_00:c4:e1 (00:15:5d:00:c4:e1)
Internet Protocol Version 4, Src: 172.18.216.210, Dst: 142.251.36.142
Transmission Control Protocol, Src Port: 47351, Dst Port: 80, Seq: 0, Len: 0

0000   00 15 5d 00 c4 e1 00 15 5d 0c c9 5c 08 00 45 00   ..].....]..\..E.
0010   00 28 54 99 00 00 40 06 ed c8 ac 12 d8 d2 8e fb   .(T...@.........
0020   24 8e b8 f7 00 50 e6 d5 ea f6 00 00 00 00 50 02   $....P........P.
0030   05 c8 e6 97 00 00                                 ......
```

#### Actual output:
```console
$ sudo ./ipk-sniffer -i eth0 --tcp
timestamp: 2023-04-17T16:38:33.732+02:00
src MAC: 00:15:5d:00:c4:e1
dst MAC: 00:15:5d:0c:c9:5c
frame length: 54 bytes
src IP: 172.18.216.210
dst IP: 142.251.36.142
src port: 47351
dst port: 80

0x0000: 00 15 5d 00 c4 e1 00 15 5d 0c c9 5c 08 00 45 00 ..]..... ]..\..E.
0x0010: 00 28 54 99 00 00 40 06 ed c8 ac 12 d8 d2 8e fb .(T...@. ........
0x0020: 24 8e b8 f7 00 50 e6 d5 ea f6 00 00 00 00 50 02 $....P.. ......P.
0x0030: 05 c8 e6 97 00 00                               ......

```

### Test 10: Sniffing only **UDP** packets from the `eth0` interface:

#### Input:
```console
$ sudo nping --udp google.com

Starting Nping 0.7.80 ( https://nmap.org/nping ) at 2023-04-17 16:42 CEST
SENT (0.0703s) UDP 172.18.216.210:53 > 142.251.36.142:40125 ttl=64 id=29964 iplen=28 
^C 
Max rtt: N/A | Min rtt: N/A | Avg rtt: N/A
Raw packets sent: 1 (28B) | Rcvd: 0 (0B) | Lost: 1 (100.00%)
Nping done: 1 IP address pinged in 0.30 seconds
```

#### Expected output:
```console
Frame 250: 70 bytes on wire (560 bits), 70 bytes captured (560 bits) on interface eth0, id 0
    Section number: 1
    Interface id: 0 (eth0)
    Encapsulation type: Ethernet (1)
    Arrival Time: Apr 17, 2023 16:42:38.081970190 CEST
    [Time shift for this packet: 0.000000000 seconds]
    Epoch Time: 1681742558.081970190 seconds
    [Time delta from previous captured frame: 2.421049669 seconds]
    [Time delta from previous displayed frame: 2.421049669 seconds]
    [Time since reference or first frame: 1450.590559398 seconds]
    Frame Number: 250
    Frame Length: 70 bytes (560 bits)
    Capture Length: 70 bytes (560 bits)
    [Frame is marked: False]
    [Frame is ignored: False]
    [Protocols in frame: eth:ethertype:ip:udp:dns]
    [Coloring Rule Name: UDP]
    [Coloring Rule String: udp]
Ethernet II, Src: Microsof_0c:c9:5c (00:15:5d:0c:c9:5c), Dst: Microsof_00:c4:e1 (00:15:5d:00:c4:e1)
Internet Protocol Version 4, Src: 172.18.216.210, Dst: 172.18.208.1
User Datagram Protocol, Src Port: 58100, Dst Port: 53
Domain Name System (query)
    Transaction ID: 0xf366
    Flags: 0x0100 Standard query
    Questions: 1
    Answer RRs: 0
    Authority RRs: 0
    Additional RRs: 0
    Queries
        google.com: type A, class IN
            Name: google.com
            [Name Length: 10]
            [Label Count: 2]
            Type: A (Host Address) (1)
            Class: IN (0x0001)
    [Response In: 251]
    
0000   00 15 5d 00 c4 e1 00 15 5d 0c c9 5c 08 00 45 00   ..].....]..\..E.
0010   00 38 c2 aa 40 00 40 11 77 11 ac 12 d8 d2 ac 12   .8..@.@.w.......
0020   d0 01 e2 f4 00 35 00 24 01 2f f3 66 01 00 00 01   .....5.$./.f....
0030   00 00 00 00 00 00 06 67 6f 6f 67 6c 65 03 63 6f   .......google.co
0040   6d 00 00 01 00 01                                 m.....
```

#### Actual output:
```console
$ sudo ./ipk-sniffer -i eth0 --udp
timestamp: 2023-04-17T16:42:38.081+02:00
src MAC: 00:15:5d:00:c4:e1
dst MAC: 00:15:5d:0c:c9:5c
frame length: 70 bytes
src IP: 172.18.216.210
dst IP: 172.18.208.1
src port: 58100
dst port: 53

0x0000: 00 15 5d 00 c4 e1 00 15 5d 0c c9 5c 08 00 45 00 ..]..... ]..\..E.
0x0010: 00 38 c2 aa 40 00 40 11 77 11 ac 12 d8 d2 ac 12 .8..@.@. w.......
0x0020: d0 01 e2 f4 00 35 00 24 01 2f f3 66 01 00 00 01 .....5.$ ./.f....
0x0030: 00 00 00 00 00 00 06 67 6f 6f 67 6c 65 03 63 6f .......g oogle.co
0x0040: 6d 00 00 01 00 01                               m.....

```

### Test 11: Sniffing **TCP** or **UDP** packets from the `eth0` interface:

#### Input:
```console
$ telnet google.com
Trying 142.251.36.142...
^C
```

#### Expected output:
```console
Frame 300: 70 bytes on wire (560 bits), 70 bytes captured (560 bits) on interface eth0, id 0
    Section number: 1
    Interface id: 0 (eth0)
    Encapsulation type: Ethernet (1)
    Arrival Time: Apr 17, 2023 16:47:19.441439523 CEST
    [Time shift for this packet: 0.000000000 seconds]
    Epoch Time: 1681742839.441439523 seconds
    [Time delta from previous captured frame: 6.842307236 seconds]
    [Time delta from previous displayed frame: 6.842307236 seconds]
    [Time since reference or first frame: 1731.950028731 seconds]
    Frame Number: 300
    Frame Length: 70 bytes (560 bits)
    Capture Length: 70 bytes (560 bits)
    [Frame is marked: False]
    [Frame is ignored: False]
    [Protocols in frame: eth:ethertype:ip:udp:dns]
    [Coloring Rule Name: UDP]
    [Coloring Rule String: udp]
Ethernet II, Src: Microsof_0c:c9:5c (00:15:5d:0c:c9:5c), Dst: Microsof_00:c4:e1 (00:15:5d:00:c4:e1)
Internet Protocol Version 4, Src: 172.18.216.210, Dst: 172.18.208.1
User Datagram Protocol, Src Port: 45884, Dst Port: 53
Domain Name System (query)
    Transaction ID: 0x0d4d
    Flags: 0x0100 Standard query
    Questions: 1
    Answer RRs: 0
    Authority RRs: 0
    Additional RRs: 0
    Queries
        google.com: type A, class IN
            Name: google.com
            [Name Length: 10]
            [Label Count: 2]
            Type: A (Host Address) (1)
            Class: IN (0x0001)
    [Response In: 302]

0000   00 15 5d 00 c4 e1 00 15 5d 0c c9 5c 08 00 45 00   ..].....]..\..E.
0010   00 38 e9 4c 40 00 40 11 50 6f ac 12 d8 d2 ac 12   .8.L@.@.Po......
0020   d0 01 b3 3c 00 35 00 24 01 2f 0d 4d 01 00 00 01   ...<.5.$./.M....
0030   00 00 00 00 00 00 06 67 6f 6f 67 6c 65 03 63 6f   .......google.co
0040   6d 00 00 01 00 01                                 m.....

```
#### Actual output:
```console
$ sudo ./ipk-sniffer -i eth0 --tcp --udp
timestamp: 2023-04-17T16:47:19.441+02:00
src MAC: 00:15:5d:00:c4:e1
dst MAC: 00:15:5d:0c:c9:5c
frame length: 70 bytes
src IP: 172.18.216.210
dst IP: 172.18.208.1
src port: 45884
dst port: 53

0x0000: 00 15 5d 00 c4 e1 00 15 5d 0c c9 5c 08 00 45 00 ..]..... ]..\..E.
0x0010: 00 38 e9 4c 40 00 40 11 50 6f ac 12 d8 d2 ac 12 .8.L@.@. Po......
0x0020: d0 01 b3 3c 00 35 00 24 01 2f 0d 4d 01 00 00 01 ...<.5.$ ./.M....
0x0030: 00 00 00 00 00 00 06 67 6f 6f 67 6c 65 03 63 6f .......g oogle.co
0x0040: 6d 00 00 01 00 01                               m.....

```

## Section 4: Filtering by destination port 

### Test 12: Sniffing **TCP** or **UDP** packets from the `eth0` interface with port `23`

#### Input:
```console
$ telnet google.com 23
Trying 142.251.36.142...
^C
```

#### Expected output:
```console
Frame 361: 74 bytes on wire (592 bits), 74 bytes captured (592 bits) on interface eth0, id 0
    Section number: 1
    Interface id: 0 (eth0)
    Encapsulation type: Ethernet (1)
    Arrival Time: Apr 17, 2023 16:51:47.736940929 CEST
    [Time shift for this packet: 0.000000000 seconds]
    Epoch Time: 1681743107.736940929 seconds
    [Time delta from previous captured frame: 0.000529538 seconds]
    [Time delta from previous displayed frame: 0.000529538 seconds]
    [Time since reference or first frame: 2000.245530137 seconds]
    Frame Number: 361
    Frame Length: 74 bytes (592 bits)
    Capture Length: 74 bytes (592 bits)
    [Frame is marked: False]
    [Frame is ignored: False]
    [Protocols in frame: eth:ethertype:ip:tcp]
    [Coloring Rule Name: TCP SYN/FIN]
    [Coloring Rule String: tcp.flags & 0x02 || tcp.flags.fin == 1]
Ethernet II, Src: Microsof_0c:c9:5c (00:15:5d:0c:c9:5c), Dst: Microsof_00:c4:e1 (00:15:5d:00:c4:e1)
Internet Protocol Version 4, Src: 172.18.216.210, Dst: 142.251.36.142
Transmission Control Protocol, Src Port: 58884, Dst Port: 23, Seq: 0, Len: 0

0000   00 15 5d 00 c4 e1 00 15 5d 0c c9 5c 08 00 45 10   ..].....]..\..E.
0010   00 3c 8a c3 40 00 40 06 77 7a ac 12 d8 d2 8e fb   .<..@.@.wz......
0020   24 8e e6 04 00 17 8a 87 ec d7 00 00 00 00 a0 02   $...............
0030   fa f0 38 9d 00 00 02 04 05 b4 04 02 08 0a df e1   ..8.............
0040   18 0a 00 00 00 00 01 03 03 07                     ..........
```

#### Actual output:
```console
$ sudo ./ipk-sniffer -i eth0 --tcp --udp -p 23
timestamp: 2023-04-17T16:51:47.736+02:00
src MAC: 00:15:5d:00:c4:e1
dst MAC: 00:15:5d:0c:c9:5c
frame length: 74 bytes
src IP: 172.18.216.210
dst IP: 142.251.36.142
src port: 58884
dst port: 23

0x0000: 00 15 5d 00 c4 e1 00 15 5d 0c c9 5c 08 00 45 10 ..]..... ]..\..E.
0x0010: 00 3c 8a c3 40 00 40 06 77 7a ac 12 d8 d2 8e fb .<..@.@. wz......
0x0020: 24 8e e6 04 00 17 8a 87 ec d7 00 00 00 00 a0 02 $....... ........
0x0030: fa f0 38 9d 00 00 02 04 05 b4 04 02 08 0a df e1 ..8..... ........
0x0040: 18 0a 00 00 00 00 01 03 03 07                   ........ ..

```

## Section 5: Filtering by number of packets

### Test 13: Sniffing **2** packets from the `eth0` interface:

#### Input:
```console
$ telnet google.com
Trying 142.251.36.142...
^C
```

#### Expected output:
```console
Frame 401: 70 bytes on wire (560 bits), 70 bytes captured (560 bits) on interface eth0, id 0
    Section number: 1
    Interface id: 0 (eth0)
    Encapsulation type: Ethernet (1)
    Arrival Time: Apr 17, 2023 16:55:55.644104061 CEST
    [Time shift for this packet: 0.000000000 seconds]
    Epoch Time: 1681743355.644104061 seconds
    [Time delta from previous captured frame: 12.860209206 seconds]
    [Time delta from previous displayed frame: 12.860209206 seconds]
    [Time since reference or first frame: 2248.152693269 seconds]
    Frame Number: 401
    Frame Length: 70 bytes (560 bits)
    Capture Length: 70 bytes (560 bits)
    [Frame is marked: False]
    [Frame is ignored: False]
    [Protocols in frame: eth:ethertype:ip:udp:dns]
    [Coloring Rule Name: UDP]
    [Coloring Rule String: udp]
Ethernet II, Src: Microsof_0c:c9:5c (00:15:5d:0c:c9:5c), Dst: Microsof_00:c4:e1 (00:15:5d:00:c4:e1)
Internet Protocol Version 4, Src: 172.18.216.210, Dst: 172.18.208.1
User Datagram Protocol, Src Port: 38249, Dst Port: 53
Domain Name System (query)
    Transaction ID: 0x122d
    Flags: 0x0100 Standard query
    Questions: 1
    Answer RRs: 0
    Authority RRs: 0
    Additional RRs: 0
    Queries
        google.com: type A, class IN
            Name: google.com
            [Name Length: 10]
            [Label Count: 2]
            Type: A (Host Address) (1)
            Class: IN (0x0001)
    [Response In: 403]

0000   00 15 5d 00 c4 e1 00 15 5d 0c c9 5c 08 00 45 00   ..].....]..\..E.
0010   00 38 67 2d 40 00 40 11 d2 8e ac 12 d8 d2 ac 12   .8g-@.@.........
0020   d0 01 95 69 00 35 00 24 01 2f 12 2d 01 00 00 01   ...i.5.$./.-....
0030   00 00 00 00 00 00 06 67 6f 6f 67 6c 65 03 63 6f   .......google.co
0040   6d 00 00 01 00 01                                 m.....

Frame 402: 70 bytes on wire (560 bits), 70 bytes captured (560 bits) on interface eth0, id 0
    Section number: 1
    Interface id: 0 (eth0)
    Encapsulation type: Ethernet (1)
    Arrival Time: Apr 17, 2023 16:55:55.644122296 CEST
    [Time shift for this packet: 0.000000000 seconds]
    Epoch Time: 1681743355.644122296 seconds
    [Time delta from previous captured frame: 0.000018235 seconds]
    [Time delta from previous displayed frame: 0.000018235 seconds]
    [Time since reference or first frame: 2248.152711504 seconds]
    Frame Number: 402
    Frame Length: 70 bytes (560 bits)
    Capture Length: 70 bytes (560 bits)
    [Frame is marked: False]
    [Frame is ignored: False]
    [Protocols in frame: eth:ethertype:ip:udp:dns]
    [Coloring Rule Name: UDP]
    [Coloring Rule String: udp]
Ethernet II, Src: Microsof_0c:c9:5c (00:15:5d:0c:c9:5c), Dst: Microsof_00:c4:e1 (00:15:5d:00:c4:e1)
Internet Protocol Version 4, Src: 172.18.216.210, Dst: 172.18.208.1
User Datagram Protocol, Src Port: 38249, Dst Port: 53
Domain Name System (query)
    Transaction ID: 0x9b53
    Flags: 0x0100 Standard query
    Questions: 1
    Answer RRs: 0
    Authority RRs: 0
    Additional RRs: 0
    Queries
        google.com: type AAAA, class IN
            Name: google.com
            [Name Length: 10]
            [Label Count: 2]
            Type: AAAA (IPv6 Address) (28)
            Class: IN (0x0001)
    [Response In: 404]

0000   00 15 5d 00 c4 e1 00 15 5d 0c c9 5c 08 00 45 00   ..].....]..\..E.
0010   00 38 67 2e 40 00 40 11 d2 8d ac 12 d8 d2 ac 12   .8g.@.@.........
0020   d0 01 95 69 00 35 00 24 01 2f 9b 53 01 00 00 01   ...i.5.$./.S....
0030   00 00 00 00 00 00 06 67 6f 6f 67 6c 65 03 63 6f   .......google.co
0040   6d 00 00 1c 00 01                                 m.....

```

#### Actual output:
```console
$ sudo ./ipk-sniffer -i eth0 -n 2
timestamp: 2023-04-17T16:55:55.644+02:00
src MAC: 00:15:5d:00:c4:e1
dst MAC: 00:15:5d:0c:c9:5c
frame length: 70 bytes
src IP: 172.18.216.210
dst IP: 172.18.208.1
src port: 38249
dst port: 53

0x0000: 00 15 5d 00 c4 e1 00 15 5d 0c c9 5c 08 00 45 00 ..]..... ]..\..E.
0x0010: 00 38 67 2d 40 00 40 11 d2 8e ac 12 d8 d2 ac 12 .8g-@.@. ........
0x0020: d0 01 95 69 00 35 00 24 01 2f 12 2d 01 00 00 01 ...i.5.$ ./.-....
0x0030: 00 00 00 00 00 00 06 67 6f 6f 67 6c 65 03 63 6f .......g oogle.co
0x0040: 6d 00 00 01 00 01                               m.....

timestamp: 2023-04-17T16:55:55.644+02:00
src MAC: 00:15:5d:00:c4:e1
dst MAC: 00:15:5d:0c:c9:5c
frame length: 70 bytes
src IP: 172.18.216.210
dst IP: 172.18.208.1
src port: 38249
dst port: 53

0x0000: 00 15 5d 00 c4 e1 00 15 5d 0c c9 5c 08 00 45 00 ..]..... ]..\..E.
0x0010: 00 38 67 2e 40 00 40 11 d2 8d ac 12 d8 d2 ac 12 .8g.@.@. ........
0x0020: d0 01 95 69 00 35 00 24 01 2f 9b 53 01 00 00 01 ...i.5.$ ./.S....
0x0030: 00 00 00 00 00 00 06 67 6f 6f 67 6c 65 03 63 6f .......g oogle.co
0x0040: 6d 00 00 1c 00 01                               m.....

```

### Test 14: Sniffing **2** **TCP** or **NDP** packets from the `eth0` interface:

#### Input:
```console
$ sudo python3.10 tests/skripts/ndp.py
.
Sent 1 packets.
```

#### Expected output:
```console
Frame 466: 86 bytes on wire (688 bits), 86 bytes captured (688 bits) on interface eth0, id 0
    Section number: 1
    Interface id: 0 (eth0)
    Encapsulation type: Ethernet (1)
    Arrival Time: Apr 17, 2023 17:00:53.001077732 CEST
    [Time shift for this packet: 0.000000000 seconds]
    Epoch Time: 1681743653.001077732 seconds
    [Time delta from previous captured frame: 6.126335380 seconds]
    [Time delta from previous displayed frame: 6.126335380 seconds]
    [Time since reference or first frame: 2545.509666940 seconds]
    Frame Number: 466
    Frame Length: 86 bytes (688 bits)
    Capture Length: 86 bytes (688 bits)
    [Frame is marked: False]
    [Frame is ignored: False]
    [Protocols in frame: eth:ethertype:ipv6:icmpv6]
    [Coloring Rule Name: ICMP]
    [Coloring Rule String: icmp || icmpv6]
Ethernet II, Src: Microsof_0c:c9:5c (00:15:5d:0c:c9:5c), Dst: IPv6mcast_ff:00:12:34 (33:33:ff:00:12:34)
Internet Protocol Version 6, Src: fe80::215:5dff:fe0c:c95c, Dst: ff02::1:ff00:1234
Internet Control Message Protocol v6

0000   33 33 ff 00 12 34 00 15 5d 0c c9 5c 86 dd 60 00   33...4..]..\..`.
0010   00 00 00 20 3a ff fe 80 00 00 00 00 00 00 02 15   ... :...........
0020   5d ff fe 0c c9 5c ff 02 00 00 00 00 00 00 00 00   ]....\..........
0030   00 01 ff 00 12 34 87 00 0a 39 00 00 00 00 fe 80   .....4...9......
0040   00 00 00 00 00 00 00 00 00 00 00 00 12 34 01 01   .............4..
0050   00 15 5d 0c c9 5c                                 ..]..\

Frame 467: 70 bytes on wire (560 bits), 70 bytes captured (560 bits) on interface eth0, id 0
    Section number: 1
    Interface id: 0 (eth0)
    Encapsulation type: Ethernet (1)
    Arrival Time: Apr 17, 2023 17:00:54.046579876 CEST
    [Time shift for this packet: 0.000000000 seconds]
    Epoch Time: 1681743654.046579876 seconds
    [Time delta from previous captured frame: 1.045502144 seconds]
    [Time delta from previous displayed frame: 1.045502144 seconds]
    [Time since reference or first frame: 2546.555169084 seconds]
    Frame Number: 467
    Frame Length: 70 bytes (560 bits)
    Capture Length: 70 bytes (560 bits)
    [Frame is marked: False]
    [Frame is ignored: False]
    [Protocols in frame: eth:ethertype:ipv6:icmpv6]
    [Coloring Rule Name: ICMP]
    [Coloring Rule String: icmp || icmpv6]
Ethernet II, Src: Microsof_0c:c9:5c (00:15:5d:0c:c9:5c), Dst: Broadcast (ff:ff:ff:ff:ff:ff)
Internet Protocol Version 6, Src: fe80::215:5dff:fe0c:c95c, Dst: fe80::1234
Internet Control Message Protocol v6

0000   ff ff ff ff ff ff 00 15 5d 0c c9 5c 86 dd 60 00   ........]..\..`.
0010   00 00 00 10 3a ff fe 80 00 00 00 00 00 00 02 15   ....:...........
0020   5d ff fe 0c c9 5c fe 80 00 00 00 00 00 00 00 00   ]....\..........
0030   00 00 00 00 12 34 85 00 72 ca 00 00 00 00 01 01   .....4..r.......
0040   01 23 45 67 89 ab                                 .#Eg..

```

#### Actual output:
```console
$ sudo ./ipk-sniffer -i eth0 --tcp --ndp -n 2
timestamp: 2023-04-17T17:00:53.001+02:00
src MAC: 33:33:ff:00:12:34
dst MAC: 00:15:5d:0c:c9:5c
frame length: 86 bytes

0x0000: 33 33 ff 00 12 34 00 15 5d 0c c9 5c 86 dd 60 00 33...4.. ]..\..`.
0x0010: 00 00 00 20 3a ff fe 80 00 00 00 00 00 00 02 15 ... :... ........
0x0020: 5d ff fe 0c c9 5c ff 02 00 00 00 00 00 00 00 00 ]....\.. ........
0x0030: 00 01 ff 00 12 34 87 00 0a 39 00 00 00 00 fe 80 .....4.. .9......
0x0040: 00 00 00 00 00 00 00 00 00 00 00 00 12 34 01 01 ........ .....4..
0x0050: 00 15 5d 0c c9 5c                               ..]..\

timestamp: 2023-04-17T17:00:54.046+02:00
src MAC: ff:ff:ff:ff:ff:ff
dst MAC: 00:15:5d:0c:c9:5c
frame length: 70 bytes

0x0000: ff ff ff ff ff ff 00 15 5d 0c c9 5c 86 dd 60 00 ........ ]..\..`.
0x0010: 00 00 00 10 3a ff fe 80 00 00 00 00 00 00 02 15 ....:... ........
0x0020: 5d ff fe 0c c9 5c fe 80 00 00 00 00 00 00 00 00 ]....\.. ........
0x0030: 00 00 00 00 12 34 85 00 72 ca 00 00 00 00 01 01 .....4.. r.......
0x0040: 01 23 45 67 89 ab                               .#Eg..

```

## Section 6: Trying to sniff from different interfaces:

### Test 15: Sniffing packet from the `eth0` interface:

#### Input:
```console
$ ping -I eth0 google.com
PING google.com (142.251.36.142) from 172.18.216.210 eth0: 56(84) bytes of data.
64 bytes from prg03s12-in-f14.1e100.net (142.251.36.142): icmp_seq=1 ttl=116 time=18.7 ms
^C
--- google.com ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 18.687/18.687/18.687/0.000 ms
```

#### Expected output:
```console
Frame 22: 70 bytes on wire (560 bits), 70 bytes captured (560 bits) on interface eth0, id 0
    Section number: 1
    Interface id: 0 (eth0)
    Encapsulation type: Ethernet (1)
    Arrival Time: Apr 17, 2023 17:17:56.206650818 CEST
    [Time shift for this packet: 0.000000000 seconds]
    Epoch Time: 1681744676.206650818 seconds
    [Time delta from previous captured frame: 7.506030647 seconds]
    [Time delta from previous displayed frame: 7.506030647 seconds]
    [Time since reference or first frame: 42.930137445 seconds]
    Frame Number: 22
    Frame Length: 70 bytes (560 bits)
    Capture Length: 70 bytes (560 bits)
    [Frame is marked: False]
    [Frame is ignored: False]
    [Protocols in frame: eth:ethertype:ip:udp:dns]
    [Coloring Rule Name: UDP]
    [Coloring Rule String: udp]
Ethernet II, Src: Microsof_0c:c9:5c (00:15:5d:0c:c9:5c), Dst: Microsof_00:c4:e1 (00:15:5d:00:c4:e1)
Internet Protocol Version 4, Src: 172.18.216.210, Dst: 172.18.208.1
User Datagram Protocol, Src Port: 59057, Dst Port: 53
Domain Name System (query)
    Transaction ID: 0xcfb2
    Flags: 0x0100 Standard query
    Questions: 1
    Answer RRs: 0
    Authority RRs: 0
    Additional RRs: 0
    Queries
        google.com: type A, class IN
            Name: google.com
            [Name Length: 10]
            [Label Count: 2]
            Type: A (Host Address) (1)
            Class: IN (0x0001)
    [Response In: 24]

0000   00 15 5d 00 c4 e1 00 15 5d 0c c9 5c 08 00 45 00   ..].....]..\..E.
0010   00 38 3c 9b 40 00 40 11 fd 20 ac 12 d8 d2 ac 12   .8<.@.@.. ......
0020   d0 01 e6 b1 00 35 00 24 01 2f cf b2 01 00 00 01   .....5.$./......
0030   00 00 00 00 00 00 06 67 6f 6f 67 6c 65 03 63 6f   .......google.co
0040   6d 00 00 01 00 01                                 m.....
```

#### Actual output:
```console
$ sudo ./ipk-sniffer -i eth0
timestamp: 2023-04-17T17:17:56.206+02:00
src MAC: 00:15:5d:00:c4:e1
dst MAC: 00:15:5d:0c:c9:5c
frame length: 70 bytes
src IP: 172.18.216.210
dst IP: 172.18.208.1
src port: 59057
dst port: 53

0x0000: 00 15 5d 00 c4 e1 00 15 5d 0c c9 5c 08 00 45 00 ..]..... ]..\..E.
0x0010: 00 38 3c 9b 40 00 40 11 fd 20 ac 12 d8 d2 ac 12 .8<.@.@. . ......
0x0020: d0 01 e6 b1 00 35 00 24 01 2f cf b2 01 00 00 01 .....5.$ ./......
0x0030: 00 00 00 00 00 00 06 67 6f 6f 67 6c 65 03 63 6f .......g oogle.co
0x0040: 6d 00 00 01 00 01                               m.....

```

### Test 16: Sniffing packet from the `any` interface:

#### Input:
```console
$ ping google.com
PING google.com (142.251.36.142) 56(84) bytes of data.
64 bytes from prg03s12-in-f14.1e100.net (142.251.36.142): icmp_seq=1 ttl=116 time=18.3 ms
^C
--- google.com ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 18.324/18.324/18.324/0.000 ms
```

#### Expected output:
```console
Frame 2: 72 bytes on wire (576 bits), 72 bytes captured (576 bits) on interface any, id 0
    Section number: 1
    Interface id: 0 (any)
    Encapsulation type: Linux cooked-mode capture v1 (25)
    Arrival Time: Apr 17, 2023 17:24:21.926228231 CEST
    [Time shift for this packet: 0.000000000 seconds]
    Epoch Time: 1681745061.926228231 seconds
    [Time delta from previous captured frame: 8.533064576 seconds]
    [Time delta from previous displayed frame: 8.533064576 seconds]
    [Time since reference or first frame: 8.533064576 seconds]
    Frame Number: 2
    Frame Length: 72 bytes (576 bits)
    Capture Length: 72 bytes (576 bits)
    [Frame is marked: False]
    [Frame is ignored: False]
    [Protocols in frame: sll:ethertype:ip:udp:dns]
    [Coloring Rule Name: UDP]
    [Coloring Rule String: udp]
Linux cooked capture v1
Internet Protocol Version 4, Src: 172.18.216.210, Dst: 172.18.208.1
User Datagram Protocol, Src Port: 56053, Dst Port: 53
Domain Name System (query)
    Transaction ID: 0xdba0
    Flags: 0x0100 Standard query
    Questions: 1
    Answer RRs: 0
    Authority RRs: 0
    Additional RRs: 0
    Queries
        google.com: type A, class IN
            Name: google.com
            [Name Length: 10]
            [Label Count: 2]
            Type: A (Host Address) (1)
            Class: IN (0x0001)
    [Response In: 4]

0000   00 04 00 01 00 06 00 15 5d 0c c9 5c 00 00 08 00   ........]..\....
0010   45 00 00 38 df 0f 40 00 40 11 5a ac ac 12 d8 d2   E..8..@.@.Z.....
0020   ac 12 d0 01 da f5 00 35 00 24 01 2f db a0 01 00   .......5.$./....
0030   00 01 00 00 00 00 00 00 06 67 6f 6f 67 6c 65 03   .........google.
0040   63 6f 6d 00 00 01 00 01                           com.....
```

#### Actual output:
```console
$ sudo ./ipk-sniffer -i any
timestamp: 2023-04-17T17:24:21.926+02:00
src MAC: 00:04:00:01:00:06
dst MAC: 00:15:5d:0c:c9:5c
frame length: 72 bytes

0x0000: 00 04 00 01 00 06 00 15 5d 0c c9 5c 00 00 08 00 ........ ]..\....
0x0010: 45 00 00 38 df 0f 40 00 40 11 5a ac ac 12 d8 d2 E..8..@. @.Z.....
0x0020: ac 12 d0 01 da f5 00 35 00 24 01 2f db a0 01 00 .......5 .$./....
0x0030: 00 01 00 00 00 00 00 00 06 67 6f 6f 67 6c 65 03 ........ .google.
0x0040: 63 6f 6d 00 00 01 00 01                         com.....
```

## Bibliography

- [1]  Gravé, V. (n.d.). Develop a Packet Sniffer with Libpcap [Web log post]. Retrieved from https://vichargrave.github.io/programming/develop-a-packet-sniffer-with-libpcap/
- [2] García, L.M. (2010). Programming with Libpcap [PDF]. Hakin9 Magazine. Retrieved from http://recursos.aldabaknocking.com/libpcapHakin9LuisMartinGarcia.pdf
- [3] The Tcpdump Group (2018). Programming with pcap [Web page]. Retrieved from https://www.tcpdump.org/pcap.html
- [4] Watcom C/C++ Programmer’s Guide (1996). Header Files [Web page]. Retrieved from https://users.pja.edu.pl/~jms/qnx/help/watcom/clibref/headers.html
- [5] IANA (2018). Protocol Numbers [Web page]. Retrieved from https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
- [6] Wikipedia contributors (2023). IP address [Web page]. In Wikipedia, The Free Encyclopedia. Retrieved April 16, 2023, from https://en.wikipedia.org/wiki/IP_address
- [7] Wikipedia contributors (2023). Transmission Control Protocol [Web page]. In Wikipedia, The Free Encyclopedia. Retrieved April 16, 2023, from https://en.wikipedia.org/wiki/Transmission_Control_Protocol
- [8] Wikipedia contributors (2023). User Datagram Protocol [Web page]. In Wikipedia, The Free Encyclopedia. Retrieved April 16, 2023, from https://en.wikipedia.org/wiki/User_Datagram_Protocol
- [9] Wikipedia contributors (2023). Internet Protocol version 4 [Web page]. In Wikipedia, The Free Encyclopedia. Retrieved April 16, 2023, from https://en.wikipedia.org/wiki/IPv4
- [10] RFC Editor (2017). STD 86 RFC 8200 Internet Protocol, Version 6 (IPv6) Specification [PDF]. Retrieved from https://www.rfc-editor.org/info/rfc8200
- [11] Wikipedia contributors (2023). Internet Protocol version 6 [Web page]. In Wikipedia, The Free Encyclopedia. Retrieved April 16, 2023, from https://en.wikipedia.org/wiki/IPv6
- [12] RFC Editor (1999). RFC 2675 IPv6 Jumbograms [PDF]. Retrieved from https://www.rfc-editor.org/info/rfc2675
- [13] Wikipedia contributors (2023). ICMPv6 [Web page]. In Wikipedia, The Free Encyclopedia. Retrieved April 16, 2023, from https://en.wikipedia.org/wiki/ICMPv6
- [14] Linux man pages (2018). inet_ntop(3) — Linux manual page [Web page]. Retrieved from https://man7.org/linux/man-pages/man3/inet_ntop.3.html
- [15] Wikipedia contributors (2023). Address Resolution Protocol [Web page]. In Wikipedia, The Free Encyclopedia. Retrieved April 16, 2023, from https://en.wikipedia.org/wiki/Address_Resolution_Protocol
- [16] Wikipedia contributors (2023). Internet Group Management Protocol [Web page]. In Wikipedia, The Free Encyclopedia. Retrieved April 16, 2023, from https://en.wikipedia.org/wiki/Internet_Group_Management_Protocol
- [17] Wikipedia contributors (2023). Neighbor Discovery Protocol [Web page]. In Wikipedia, The Free Encyclopedia. Retrieved April 16, 2023, from https://en.wikipedia.org/wiki/Neighbor_Discovery_Protocol
- [18] Wikipedia contributors (2023). Multicast Listener Discovery [Web page]. In Wikipedia, The Free Encyclopedia. Retrieved April 16, 2023, from https://en.wikipedia.org/wiki/Multicast_Listener_Discovery