# Ping

Implementation of ping in Go with support for Windows, Linux and MacOS. 
The function of pinging is implemented by **sending** ICMP **ECHO_REQUEST** messages and **receiving** the subsequent ICMP **ECHO_REPLY** messages.


## Features

- Windows, Mac and Linux support.
- Ping hostnames (and resolve and reverse lookup their IP's), IPv4 and IPv6 Addresses.
- Outputs per-packet-received round-trip-time, packet loss and TTL.
- Outputs total packets sent, recevived, packet loss, minimum, maximum, average RTT time and std. dev.
- Supports IPv4 and IPv6.
- Handles ICMP Time Exceeded messages as well.
- Flood mode output.
- Set TTL/Hop Limit on IP Header.
- Set the the number of Echo Request packets to transmit.
- Self-Documenting Source.

## Installation

A minimal Makefile has been provided to build ping and run tests. Tested on Linux and Windows, should work on Mac.

**Build Ping**
```
  make build
  sudo ./build/ping google.com
```

**Run Test Suite**
```
  make test
```

**Clean binaries**
```
  make clean
```

## Usage

```
Usage of ping:
  -4    Use IPv4 only.
  -6    Use IPv6 only.
  -T    Alow IP TTL.
  -W duration
        Time for sent echo request to timeout. (default 2s)
  -c int
        Number of Echo Request's to send.
  -f    Flood mode.
  -i duration
        Wait interval between sending packets. (default 1s)
  -priv
        Raw ICMP Packet or UDP Ping. (default true)
  -t int
        IP Time to Live. Use with -T. (default -1)
  -v    Verbose logging.
```

### Ping google.com
```
$ sudo ./build/ping -c 3 google.com
PING del11s05-in-f14.1e100.net. (216.58.196.110) with 18 bytes of (ICMP) data
18 bytes from del11s05-in-f14.1e100.net. (216.58.196.110): packets_sent=1 packets_lost=0 ttl=0 icmp_seq=1 rtt=428.0888ms avg_rtt=428.0888ms
18 bytes from del11s05-in-f14.1e100.net. (216.58.196.110): packets_sent=2 packets_lost=0 ttl=0 icmp_seq=2 rtt=447.158114ms avg_rtt=437.623457ms
18 bytes from del11s05-in-f14.1e100.net. (216.58.196.110): packets_sent=3 packets_lost=0 ttl=0 icmp_seq=3 rtt=407.793055ms avg_rtt=427.679989ms

----------- del11s05-in-f14.1e100.net. (216.58.196.110) ping statistics -----------
3 packets transmitted, 3 received, 100.00 percent packet loss
rtt avg/mix/max/stddev = 427.679989ms/407.793055ms/447.158114ms/16.073317ms
```
### IPv6 Support
```
$ sudo ./build/ping -c 3 -6 google.com
PING del11s05-in-x0e.1e100.net. (2404:6800:4002:810::200e) with 18 bytes of (ICMP) data
18 bytes from del11s05-in-x0e.1e100.net. (2404:6800:4002:810::200e): packets_sent=1 packets_lost=0 ttl=0 icmp_seq=1 rtt=33.115739ms avg_rtt=33.115739ms
18 bytes from del11s05-in-x0e.1e100.net. (2404:6800:4002:810::200e): packets_sent=2 packets_lost=0 ttl=0 icmp_seq=2 rtt=73.349662ms avg_rtt=53.2327ms
18 bytes from del11s05-in-x0e.1e100.net. (2404:6800:4002:810::200e): packets_sent=3 packets_lost=0 ttl=0 icmp_seq=3 rtt=113.116686ms avg_rtt=73.194029ms

----------- del11s05-in-x0e.1e100.net. (2404:6800:4002:810::200e) ping statistics -----------
3 packets transmitted, 3 received, 100.00 percent packet loss
rtt avg/mix/max/stddev = 73.194029ms/33.115739ms/113.116686ms/32.660435ms
```

### Flood Mode
```
$ sudo ./build/ping -f -i 0.01s -6 google.com
PING maa03s20-in-x0e.1e100.net. (2404:6800:4007:807::200e) with 18 bytes of (ICMP) data
.......^C...
----------- maa03s20-in-x0e.1e100.net. (2404:6800:4007:807::200e) ping statistics -----------
153 packets transmitted, 146 received, 0.00 percent packet loss
rtt avg/mix/max/stddev = 71.325987ms/64.174102ms/123.084781ms/9.610944ms
```
(packets lost are the number of dots, it is high as this is a mobile network.)

## Implementation

The ping manpage, RFC#792 and the ICMP Wikipedia page have been extremely helpful in the development. The descriptive and accessibly documentation of Go packages also have been extremely helpful. 
External dependencies have been kept to a minimum, only using Go's Sub-Repositories, an external library for easier test assertions and a library for easy error handling.

I used Go's internal implementation of the ICMP protocol (`golang/x/net/icmp`) to transmit Echo Request and Echo Reply Message to an IP target. This provided structures to deal with the ICMP Message Types like Echo Request, Echo Reply and Time Exceeded, whose support has been implemented. It also provided ICMP specific PacketConnection wrapper for creating an ICMP Packet listener supporting both IPv6 and IPv4.

Ping is implemented as a seperate package in `pkg/pinger` exposing the PingConfig structure to send ping packets to a target, and return round trip time (RTT) and packet loss information. The target can be a hostname, IPv4 address or IPv6 address. Hostname's are resolved by the system resolver, a reverse hostname lookup is also performed on resolved addresses of hostnames.

Testing the implementation for IPv6 was done using an Airtel 4G (India Telecom Provider) which are known to issue IPv6 addresses via a mobile hotspot on my laptop (running Manjaro 19, Linux 5.6). In the minimal testing performed, there were often cases of TTL Time Exceeded Messages (pinging to google.com on IPv6). I didn't encounter Time Exceeded messages on my IPv4 broadband connection. More rigorous testing of the application is surely required.

### Missed Opportunities
I would like to list, what I feel, are missed opportunities. Features that I could not implement, mostly due to time constraints and other commitments.

- Improved logging
- An abstracted Pinger interface ingesting PingConfig and returning a PingResult. Seperate IPv4 and IPv6 implementations, and a Ping implementation to implment the strategy pattern and ping using the IPv4 or IPv6 implementations as determined by input flags.
- Testing of the pinging modules using nettest package for mocking connections.

## Internet Control Message Protocol (ICMP) Primer

The Internet Control Message Protocol, or ICMP, is used for communication of control and diagnostic messages. 

> Occasionally a gateway or destination host will communicate with a source host, for example, to report an error in datagram processing. For such purposes this protocol, the Internet Control Message Protocol (ICMP) is used. 
>
> \- RFC#792

There are various types of control messages available in ICMP, for implementing ping two of them are used: Echo Request and Echo Reply.

> ICMP messages are sent using the basic IP header. \- RFC#792

Fields to be used in the Internet Header for an ICMP message:
- Version
- Internet Header Length, IHL
- Type Of Service (ToS)
- Total Length (of internet data and header in octets)
- Identification, Flags, Fragment Offset
- Time to Live (in seconds)
  - The uppper bound on time of the packet existing in the network. 
  - It is decremented at machine in which the packet is processed, thus its value should be as great as the number of gateways the datagram would process.

## ICMP Message Format (for Echo/Echo Reply)

It consists of header and data section which are encapsulated in an IPv4 packet.

> The first octet of the data portion of the datagram is a ICMP type field; the value of this field determines the format of the remaining data. - RFC#792

```
        0                   1                   2                   3
Octet | 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  0  |     Type      |     Code      |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  4  |           Identifier          |        Sequence Number        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
- RFC#792

Message Format for Echo Request/Echo Reply Message

``` 
- Format for Echo Request/Echo Reply Messages
  - Datagram: ECHO_REQUEST/ECHO_REPLY
  - Addresses
    - Fields (in IP Header)
      - Source Address
      - Destination Address
    - The source and destination address in the IP header. The source in an Echo Request is simply reversed to be the destination in the subsequent Echo Reply message.
  - Type
    - 8 for Echo Request message.
    - 0 for Echo Reply message.
  - Code
    - 0
  - Checksum
    - 16-bit ones's complement of the one's complement sum of the ICMP message starting with the ICMP Type.
  - Identifier
    - An identifier to aid in matching echos and replies, may be zero.
  - Sequence Number
    - An identifier to aid in matching echos and replies, may be zero.
  - Data
    - Any subsequent data to be returned in Echo Reply.
The identifier might be used like a port in TCP or UDP to identify a session, 
and the sequence number might be incrementedon each echo request sent.  

The echoer returns these same values of identifiers in the echo reply.