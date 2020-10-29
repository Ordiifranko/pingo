package pinger

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	Log "github.com/arush15june/ping/pkg/logger"
)

// getRandomID generates an id for the icmp datagram.
func getRandomID() int {
	return rand.Intn(0xFFFF)
}

// resolveAddrType returns if the target string is an IPv4, IPv6 address or a Hostname.
// If the target is IPv4 or IPv6, the associated net.IP structure is also returned.
// If the target is not IPv4, IPv6, it is assumed to be a Hostname.
func resolveAddrType(target string) (AddrType, net.IP) {
	if addr := net.ParseIP(target); addr != nil {
		if addr.To4() == nil {
			return IP6, addr
		}
		return IP4, addr
	}

	return Hostname, nil
}

// resolveTargetAddress resolves targetName for the IP address.
// DNS resolution onccurs if the target string is a hostname, 	
// otherwise the respective IPv4 or IPv6 address is returned.
func resolveTargetAddress(networkType string, targetName string) (*net.IPAddr, error) {
	targetIpAddr, err := net.ResolveIPAddr(networkType, targetName)
	return targetIpAddr, err
}

// getICMPEchoMessage returns an ICMP Echo Request Message.
func getICMPEchoMessage(networkType string, icmpID, seq int) *icmp.Message {
	message := &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   icmpID,
			Seq:  seq,
			Data: []byte(""),
		},
	}

	switch networkType {
	case "ip6":
		message.Type = ipv6.ICMPTypeEchoRequest
	}

	return message
}

// reverseLookkupTarget looks up the target in the config for a possible hostname.
func reverseLookupTarget(targetName string) (string, error) {
	lookup := ""

	result, err := net.LookupAddr(targetName)
	if err != nil {
		return "", err
	}

	if len(result) > 0 {
		lookup = result[0]
	}

	return lookup, nil
}

// getFirstPingInfoText prints info for the ping operation
// containing hostname, resolved target, and size of packet being sent.
func getFirstPingInfoText(host string, resolved net.IP, bufSize int) string {
	return fmt.Sprintf(
		"PING %s (%s) with %d bytes of (ICMP) data",
		host,
		resolved,
		bufSize,
	)
}

// getPacketEchoReplyInfoText return information text of a EchoReplyPacket.
func getPacketEchoReplyInfoText(result *PingResult, peerLookup string, peer net.Addr, nRecvd int, replyMsg *icmp.Message, ttl int, duration time.Duration) string {
	result.resultLock.Lock()
	defer result.resultLock.Unlock()

	return fmt.Sprintf(
		"%d bytes from %s (%s): packets_sent=%d packets_lost=%d ttl=%d icmp_seq=%d rtt=%v avg_rtt=%v",
		nRecvd,
		peerLookup,
		peer,
		result.PacketSent,
		result.PacketLost,
		ttl,
		replyMsg.Body.(*icmp.Echo).Seq,
		duration,
		result.AvgRTT,
	)
}

// getPacketTimeExceededInfoText returns the information text for a Time exceeded packet to stdout.
func getPacketTimeExceededInfoText(result *PingResult, peerLookup string, peer net.Addr, nRecvd int, ttl int) string {
	result.resultLock.Lock()
	defer result.resultLock.Unlock()

	return fmt.Sprintf(
		"%d bytes from %s (%s): packets_sent=%d packets_lost=%d ttl=%d ip time exceeded",
		nRecvd,
		peerLookup,
		peer,
		result.PacketSent,
		result.PacketLost,
		ttl,
	)
}

// getNetworkType determines if the passed address IPv4 or IPv6.
// If the config.addrType is Hostname, it is assumed to be IPv4.
func getNetworkType(addrType AddrType, ForceIP4, ForceIP6 bool) string {
	networkType := "ip4"
	if addrType == IP6 {
		networkType = "ip6"
	}
	if ForceIP4 {
		networkType = "ip4"
	} else if ForceIP6 {
		networkType = "ip6"
	}

	return networkType
}

// getICMPEndpoint returns ICMP Endpoint string for Packet Listener.
// Assumes "ip" networkType to be IPv4. If higher privileges are
// available raw ICMP can be sent, if not, UDP pings are sent.
func getICMPEndpoint(networkType string, privileged bool) string {
	var endpoint string

	switch privileged {
	// privileged endpoint
	case true:
		switch networkType {
		case "ip6":
			endpoint = ICMP6EndpointPrivileged
		default:
			endpoint = ICMP4EndpointPrivileged
		}
		// unprivileged endpoint
	default:
		switch networkType {
		case "ip6":
			endpoint = ICMP6Endpoint
		default:
			endpoint = ICMP4Endpoint

		}
	}

	return endpoint
}

// getListenAddr returns the IPv4/IPv6 address Pinger will listen
// for requests on.
func getListenAddr(networkType string) string {
	listenAddr := ListenAddrIP4
	switch networkType {
	case "ip6":
		listenAddr = ListenAddrIP6
	}

	return listenAddr
}

// getICMPProtocol returns the ICMP Protocol no for the networkType.
func getICMPProtocol(networkType string) int {
	var protocol int = ProtocolICMP4
	switch networkType {
	case "ip6":
		protocol = ProtocolIPv6ICMP
	}

	return protocol
}

// getICMPParameters determines the Network Type, ICMP Endpoint, Listen Address,
// and the Protocol to be used for sending ICMP Packets.
func getICMPParameters(addrType AddrType, ForceIP4, ForceIP6, privileged bool) (string, string, string, int) {
	networkType := getNetworkType(addrType, ForceIP4, ForceIP6)

	return networkType,
		getICMPEndpoint(networkType, privileged),
		getListenAddr(networkType),
		getICMPProtocol(networkType)

}

// injectTimeInMsg replaces the value of Data in msg.Body
// replacing it with the current time in nanoseconds (UNIX Timestamp).
func injectTimeInMsg(msg *icmp.Message, injectTime time.Time) error {
	injectTimeNano := injectTime.UnixNano()
	buf := make([]byte, binary.MaxVarintLen64)
	_ = binary.PutVarint(buf, injectTimeNano)

	msg.Body.(*icmp.Echo).Data = buf

	return nil
}

// getTimeFromMsg extracts the time injected in an ICMP message
// and formats it as time.Time.
func getTimeFromMsg(msg *icmp.Message) time.Time {
	buf := msg.Body.(*icmp.Echo).Data
	time_val, _ := binary.Varint(buf)
	send_time := time.Unix(0, time_val)

	return send_time
}

// getMsgBufWithNowTime returns a buffer of bytes for an *icmp.Message with current time in
// its body.
func getMsgBufWithNowTime(msg *icmp.Message) ([]byte, int, error) {
	injectTimeInMsg(msg, time.Now())
	msgBuf, err := msg.Marshal(nil)
	if err != nil {
		Log.Debugln("getMsgBufWithNowTime(): Failed to generate message.", err)
		return nil, 0, errors.Wrap(err, "failed to produce message")
	}

	bufSize := len(msgBuf)

	return msgBuf, bufSize, nil
}

// icmpMessageEchoCompareID compares the IDs of an icmpID and the ICMP Message.
func icmpMessageEchoCompareID(icmpID int, replyMsg *icmp.Message) bool {
	return icmpID == replyMsg.Body.(*icmp.Echo).ID
}

func getEchoReplyRTT(replyMsg *icmp.Message) time.Duration {
	send_time := getTimeFromMsg(replyMsg)
	Log.Debugln("getEchoReplyRTT: Send Time (from reply):", send_time)

	return time.Now().Sub(send_time)
}
