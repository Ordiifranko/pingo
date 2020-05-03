package pinger

// Pinger provides ICMP ECHO_REQUEST handling.

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	Log "github.com/arush15june/ping/pkg/logger"
)

// IANA ProtocolNumbers
const (
	ProtocolICMP4    = 1
	ProtocolIPv6ICMP = 58
)

// ICMP4 and ICMP6 Endpoints
const (
	ICMP4EndpointPrivileged = "ip4:1"
	ICMP6EndpointPrivileged = "ip6:58"

	ICMP4Endpoint = "udp4"
	ICMP6Endpoint = "udp6"
)

// Flood mode characters.
const (
	SendChar     = "."
	ReceivedChar = "\b"
)

// Listen addresses
const (
	ListenAddrIP4 = "0.0.0.0"
	ListenAddrIP6 = "::"
)

// Address Type Constants
type AddrType int

var (
	// IP4 represents an IPv4 address.
	IP4 AddrType = 0

	// IP6 represents an IPv6 address.
	IP6 AddrType = 1

	// Hostname represents a hostname to be resolved.
	Hostname AddrType = 2
)

// CountOverError is used when PingConfig.EchoCount amoung of ICMP Echo Request's have been sent.
var CountOverError = errors.New("message count complete")

type PingConfig struct {
	// TargetName is the destination string. Could be Hostname, IPv4, IPv6.
	TargetName string

	// Target stores the target information as net.IP
	Target *net.IPAddr

	// ForceIP4 forces IPv4 Usage.
	ForceIP4 bool

	// ForceIP6 forces IPv6 Usage
	ForceIP6 bool

	// EchoCount is the number of the ECHO datagrams to send.
	EchoCount int

	// Timeout is the time after which requests timeout. (Default 1s)
	Timeout time.Duration

	// Interval is the time between sending packets.
	Interval time.Duration

	// TTL is the IP Time to Live.
	TTL int

	// AllowTTL allows setting TTL in IP Header.
	AllowTTL bool

	// Flood enables flood mode where sent packet is printed to stdout as . and received packet as backspace.
	Flood bool

	// Privilege if enabled sends raw ICMP packets (requires superuser in linux, works in windows), else UDP packets are sent to implement ping.
	Privilege bool

	// Lookup is the reverse lookup of the resolved Target.
	Lookup string

	// Result stores the result of the ping.
	Result *PingResult

	// AddressType is the address type of the target. Hostname, IPv4, IPv6.
	addrType AddrType

	// ip is the ip buffer as returned by resolveAddrType.
	ip net.IP

	// networkType is the network string used by various net.* utilities.
	networkType string

	// icmpID is the ICMP datagram ID. 2-octets in ICMP datagram.
	// This will remain constant throughout our ping operation.
	icmpID int

	// seq is the sequence number used to aid in identification
	// of ICMP packets.
	seq int

	// protocol selects the ICMP v4 or v6 protocol numbers.
	protocol int
}

type PingResult struct {
	// RTT stores the RTT of all packets. Indexed by Sequence.
	RTT []time.Duration

	// Target is the destination for which the results are present.
	Target string

	// AvgRTT is the average round trip time of ICMP ECHO_REQUEST -> ECHO_REPLY. rttSum / PacketsRecvd.
	// In microseconds.
	AvgRTT time.Duration

	// MinRTT is the minimum round trip encountered.
	MinRTT time.Duration

	// MaxRTT is the maximum round trip time encountered.
	MaxRTT time.Duration

	// PacketSent is the number of packets sent in the ping process.
	PacketSent int

	// PacketRecvd is the number of packets received in the ping process.
	PacketRecvd int

	// PacketLost is the number of packets lost in the ping process.
	PacketLost int

	// rttSum is the current sum of RTT's.
	rttSum time.Duration

	resultLock *sync.Mutex
}

// NewPing creates a new ping configuration, and resolves the address type of target.
func NewPing(
	target string,
	ip4 bool,
	ip6 bool,
	count int,
	timeout time.Duration,
	ttl int,
	allowttl bool,
	interval time.Duration,
	flood bool,
	privilege bool,
) *PingConfig {

	config := &PingConfig{
		TargetName: target,
		ForceIP4:   ip4,
		ForceIP6:   ip6,
		EchoCount:  count,
		Timeout:    timeout,
		Interval:   interval,
		Flood:      flood,
		Privilege:  privilege,
		TTL:        ttl,
		AllowTTL:   allowttl,
		Result:     new(PingResult),
	}

	config.addrType, config.ip = resolveAddrType(target)
	config.icmpID = getRandomID()
	config.seq = 1
	config.Result.RTT = make([]time.Duration, 0)
	config.Result.resultLock = &sync.Mutex{}

	return config
}

// PacketSent increases the number of sent packets by one.
func (config *PingConfig) PacketSent() {
	config.Result.resultLock.Lock()
	defer config.Result.resultLock.Unlock()

	Log.Debugln("Sent packet,", config.seq-1)
	if config.Flood {
		fmt.Printf(SendChar)
	}
	config.Result.PacketSent += 1
}

// PacketRecvd is executed when a new packet is received, and the rtt
// of the packet is passed in. Result variables are updated and AvgRTT is computed.
func (config *PingConfig) PacketRecvd(replyMsg *icmp.Message, duration time.Duration) {
	config.Result.resultLock.Lock()
	defer config.Result.resultLock.Unlock()

	Log.Debugln("PacketRecvd: Seq:", replyMsg.Body.(*icmp.Echo).Seq, "Packet received")

	config.Result.PacketRecvd += 1
	Log.Debugln("PacketRecvd: Result.PacketSent:", config.Result.PacketSent, "ResultPacketReceived:", config.Result.PacketRecvd)
	config.Result.PacketLost = config.Result.PacketSent - config.Result.PacketRecvd
	config.Result.RTT = append(config.Result.RTT, duration)

	config.Result.rttSum += duration

	time_int := config.Result.rttSum.Nanoseconds()
	avgRtt := time.Duration(int(time_int) / config.Result.PacketRecvd)
	config.Result.AvgRTT = avgRtt * time.Nanosecond

	Log.Debugln("PacketRecvd: Seq:", replyMsg.Body.(*icmp.Echo).Seq, "New AvgRTT:", config.Result.AvgRTT)

	if duration < config.Result.MinRTT || config.Result.MinRTT == time.Duration(0) {
		config.Result.MinRTT = duration
	}

	if duration > config.Result.MaxRTT || config.Result.MaxRTT == time.Duration(0) {
		config.Result.MaxRTT = duration
	}
}

// NextMessage sends the next ICMP Message to be sent. Updates sequence
// and compares count.
func (config *PingConfig) NextMessage() (*icmp.Message, error) {
	Log.Debugln("NextMessage: next msg: seq:", config.seq, "count:", config.EchoCount, "isCountReached:", config.seq > config.EchoCount, "isCountZero:", config.EchoCount != 0)
	if config.seq > config.EchoCount && config.EchoCount != 0 {
		return nil, CountOverError
	}
	msg := getICMPEchoMessage(config.networkType, config.icmpID, config.seq)
	config.seq += 1

	return msg, nil
}

// setTTL sets the IPv4 TTL or IPv6 Hop Limit on the listener icmp.PacketConn
func (config *PingConfig) setTTL(conn *icmp.PacketConn) error {
	var err error

	if config.AllowTTL {
		switch config.networkType {
		case "ip6":
			err = conn.IPv6PacketConn().SetControlMessage(ipv6.FlagHopLimit, true)
			if err != nil {
				return errors.Wrap(err, "failed to set ipv6 hop limit flag")
			}
			if config.TTL != -1 {
				err = conn.IPv6PacketConn().SetHopLimit(config.TTL)
				if err != nil {
					return errors.Wrap(err, "failed to set ipv6 hop limit")
				}
			}
		case "ip4":
			err = conn.IPv4PacketConn().SetControlMessage(ipv4.FlagTTL, true)
			if err != nil {
				return errors.Wrap(err, "failed to set ipv4 ttl flag")
			}
			if config.TTL != -1 {
				err = conn.IPv4PacketConn().SetTTL(config.TTL)
				if err != nil {
					return errors.Wrap(err, "failed to set ipv4 ttl")
				}
			}
		}
	}

	return nil
}

// icmpListener continuously listens for packets on the passed PacketConn and passes on
// to proces packets as they are received.
// 		- Setup listener vars.
// 		- Wait until <-start signal is sent.
// 		- Start listenloop
// 			- close listenloop if <-close signal is sent.
// 			- Set a read deadline on the connection. (this doesn't block!)
// 			- Based on IPv4 or IPv4 network type, read from the connection.
// 				- Set TTL based on IPv4 TTL or IPv6 Hop Limit from IP Header.
// 			- Check for request timeout via net.OpError.
// 			- Send packet for processPacket() with buffer, peer net.Addr, nRecvd bytes and ttl.
func (config *PingConfig) icmpListener(conn *icmp.PacketConn, close chan bool, start chan bool) error {
	var err error
	var reply []byte = make([]byte, 1000)
	var nRecvd int
	var ttl int
	var peer net.Addr

	<-start

listenloop:
	for {
		select {
		case <-close:
			break listenloop
		default:
		}

		err = conn.SetReadDeadline(time.Now().Add(config.Timeout))
		if err != nil {
			Log.Debugln("icmpListener: failed setting timeout.")
		}

		switch config.networkType {
		case "ip4":
			var controlMsg *ipv4.ControlMessage
			nRecvd, controlMsg, peer, err = conn.IPv4PacketConn().ReadFrom(reply)
			if controlMsg != nil {
				ttl = controlMsg.TTL
			}

		case "ip6":
			var controlMsg *ipv6.ControlMessage
			nRecvd, controlMsg, peer, err = conn.IPv6PacketConn().ReadFrom(reply)
			if controlMsg != nil {
				ttl = controlMsg.HopLimit
			}
		}

		if err != nil {
			if neterr, ok := err.(*net.OpError); ok {
				if neterr.Timeout() {
					Log.Debugln("icmpListener:",
						errors.Wrap(err, fmt.Sprintf(
							"%s (%s): Request timeout reached\n",
							config.Lookup,
							config.Target,
						),
						),
					)
					fmt.Printf(
						"%s (%s): Request timeout reached\n",
						config.Lookup,
						config.Target,
					)
					continue
				} else {
					Log.Debugln("error receving message:", err)
					continue
				}
			}
		}

		Log.Debugln("icmpListener: Recvd packet:", nRecvd, "bytes of data, ttl=", ttl)
		config.processPacket(reply, peer, nRecvd, ttl)
	}

	return nil
}

// processPacket parses the packet for ICMP messages and prints the result.
//		- Parse ICMP message from bytestream.
// 		- Process packet based on IPv4 or IPv6 ICMP Packet Type.
// 			- Handle IPv4/IPv6 Echo Reply ICMP Packet
// 				- Compute RTT, Print info to stdout.
// 			- Handle IPv4/IPv6 Time Exceeded ICMP Packet (received when TTL expires)
// 				- Print info to stdout
// 			- Handle any other type of ICMP Packet
// 				- Print packet interface  to debug log.
func (config *PingConfig) processPacket(pkt []byte, peer net.Addr, nRecvd int, ttl int) error {
	replyMsg, err := icmp.ParseMessage(config.protocol, pkt)

	if err != nil {
		Log.Debugln("failed to parse message", err)
		return errors.New("failed to parse message")
	}

	switch replyMsg.Type {
	case ipv4.ICMPTypeEchoReply, ipv6.ICMPTypeEchoReply:
		if !icmpMessageEchoCompareID(config.icmpID, replyMsg) {
			Log.Debugln("processPacket: invalid echo id, replyMsg.ID:", replyMsg.Body.(*icmp.Echo).ID, "config.ID:", config.icmpID)
			return errors.New(fmt.Sprintf("invalid ICMP ID recvd %d", replyMsg.Body.(*icmp.Echo).ID))
		}

		rtt := getEchoReplyRTT(replyMsg)
		Log.Debugln("processPacket: RTT:", rtt)

		config.PacketRecvd(replyMsg, rtt)
		if config.Flood {
			fmt.Printf(ReceivedChar)
			return nil
		}

		info := getPacketEchoReplyInfoText(config.Result, config.Lookup, peer, nRecvd, replyMsg, ttl, rtt)
		fmt.Println(info)

	case ipv4.ICMPTypeTimeExceeded, ipv6.ICMPTypeTimeExceeded:
		info := getPacketTimeExceededInfoText(config.Result, config.Lookup, peer, nRecvd, ttl)
		fmt.Println(info)

	default:
		Log.Debugln("processPacket:", errors.New(fmt.Sprintf("invalid message: %+v", replyMsg)))
	}

	return nil
}

// Ping executes ping operation based on passed PingConfig
//		- Determine ICMP Parameters.
// 			- network type string, icmp endpoint,
// 			  listen address, icmp protocol, target address type
// 		- Resolve target, get real IP. (DNS Resolution if hostname, can take time)
// 			- returns IPv4 or IPV6 *net.IPAddr.
// 		- Reverse lookup IP if hostname. (can take time)
// 		- Setup ICMP Packet Listener
// 			- setTTL for listener.
// 		- Start icmpListener to continuosly read messages. --> Async
// 			- shared vars: config, protocol, conn, closeListener, startListener
// 		- Prepare first message.
// 			- Print initial message info.
// 		- Send signal to startListener <- 1.
// 		- Go into message sending loop.
// 		->	- Wait until message intervalDelay is fulfilled
// 		|	- Inject prepared ICMP msg with Current Time (local time, used for compare, UTC unnecessary)
// 		|	  and get message buffer to write.
// 		|	- Write bufer to Target via the PacketConnection.
// 		|	- Reset intervalDelay.
// 		|	- Add packet sent to result list.
// 		|-- - Get next prepared message.
func (config *PingConfig) Ping() (*PingResult, error) {
	var err error

	networkType, icmpEndpoint, listenAddr, protocol := getICMPParameters(config.addrType, config.ForceIP4, config.ForceIP6, config.Privilege)
	config.networkType = networkType
	config.protocol = protocol
	Log.Debugln(
		"netType:", config.networkType,
		"icmpEndpt:", icmpEndpoint,
		"listenAddr:", listenAddr,
		"protocol:", config.protocol,
		"addrTye", config.addrType,
	)

	if config.addrType == Hostname {
		targetIpAddr, err := resolveTargetAddress(config.networkType, config.TargetName)
		if err != nil {
			return nil, errors.Wrap(err, "failed to resolve target "+config.TargetName)
		}
		config.Target = targetIpAddr
		Log.Debugln("Resolved target host: ", config.TargetName, " ", config.Target.IP)
	} else {
		config.Target = &net.IPAddr{IP: config.ip}
		Log.Debugln("Using target host: ", config.TargetName, " ", config.Target.IP)
	}

	config.Lookup, _ = reverseLookupTarget(config.Target.String())
	Log.Debugln("Ping: Reverse lookup:", config.Lookup)

	conn, err := icmp.ListenPacket(icmpEndpoint, listenAddr)
	if err != nil {
		Log.Debugln("Ping: Failed listening:", icmpEndpoint, listenAddr)
		return nil, errors.Wrap(err, "failed to listen on "+listenAddr)
	}

	err = config.setTTL(conn)
	if err != nil {
		Log.Debugln("failed to set ttl:", err)
	}

	closeListener := make(chan bool)
	startListener := make(chan bool)
	go config.icmpListener(conn, closeListener, startListener)

	Log.Debugln("Ping: ICMP Listener started:", icmpEndpoint, listenAddr)
	defer func() {
		closeListener <- true
		conn.Close()
	}()

	msg, err := config.NextMessage()
	if err == CountOverError {
		return config.Result, nil
	} else if err != nil {
		Log.Debugln("Ping: Failed to get first message.")
		return nil, errors.Wrap(err, "no messages to send")
	}

	msgBuf, bufSize, err := getMsgBufWithNowTime(msg)
	if err != nil {
		return nil, err
	}
	fmt.Println(getFirstPingInfoText(config.Lookup, config.Target.IP, bufSize))

	// Messaging transmit loop.
	var intervalDelay <-chan time.Time
	startListener <- true
	for {
		if intervalDelay != nil {
			<-intervalDelay
		}

		msgBuf, bufSize, err = getMsgBufWithNowTime(msg)
		if err != nil {
			return nil, err
		}

		Log.Debugf("Ping: Sent message: %+v\n", msg)
		n, err := conn.WriteTo(msgBuf, config.Target)
		if err != nil {
			Log.Debugln("Ping: failed to write message", err)
			continue
		} else if n != bufSize {
			Log.Debugf("Ping: unequal bytes written to conn, msg=%d written=%d", bufSize, n)
			continue
		}
		intervalDelay = time.After(config.Interval)

		config.PacketSent()

		msg, err = config.NextMessage()
		if err == CountOverError {
			Log.Debugln("Ping: Message count complete")
			return config.Result, nil
		} else if err != nil {
			Log.Debugln("Ping: no more messages to send, sent=", config.Result.PacketSent)
			return nil, errors.Wrap(err, "no messages to send")
		}
	}

	return config.Result, nil
}
