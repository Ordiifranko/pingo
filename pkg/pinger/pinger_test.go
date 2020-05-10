package pinger

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func TestNewPing(t *testing.T) {
	mockPing := PingConfig{
		TargetName: "google.com",
		ForceIP4:   false,
		ForceIP6:   false,
		EchoCount:  10,
		Timeout:    5 * time.Second,
		Interval:   1 * time.Second,
		Flood:      false,
		TTL:        -1,
		AllowTTL:   false,
		Result:     &PingResult{},
	}

	newPing := NewPing(
		"google.com",
		false,
		false,
		10,
		5*time.Second,
		-1,
		false,
		1*time.Second,
		false,
		false,
	)

	assert.Equal(t, newPing.Target, mockPing.Target)
	assert.Equal(t, newPing.EchoCount, mockPing.EchoCount)
	assert.Equal(t, newPing.Timeout, mockPing.Timeout)
	assert.Equal(t, newPing.Interval, mockPing.Interval)
	assert.Equal(t, len(newPing.Result.RTT), 0)
}

func TestFirstPingInfo(t *testing.T) {
	pingInfo := getFirstPingInfoText("dns.google.com.", net.ParseIP("8.8.8.8"), 18)
	correctPingInfo := "PING dns.google.com. (8.8.8.8) with 18 bytes of (ICMP) data"

	assert.Equal(t, pingInfo, correctPingInfo)
}

func TestPacketEchoReplyInfo(t *testing.T) {
	pingResult := &PingResult{AvgRTT: 1 * time.Millisecond, PacketSent: 1, PacketLost: 0, resultLock: &sync.Mutex{}}
	echoMessage := getICMPEchoMessage("ip4", 1000, 1)
	ip := &net.IPAddr{IP: net.ParseIP("172.217.161.14")}

	pingInfo := getPacketEchoReplyInfoText(pingResult, "del03s10-in-f14.1e100.net.", ip, 18, echoMessage, 0, 1*time.Millisecond)
	correctPingInfo := "18 bytes from del03s10-in-f14.1e100.net. (172.217.161.14): packets_sent=1 packets_lost=0 ttl=0 icmp_seq=1 rtt=1ms avg_rtt=1ms"

	assert.Equal(t, pingInfo, correctPingInfo)
}

func TestPacketTimeExceededInfo(t *testing.T) {
	pingResult := &PingResult{AvgRTT: 1 * time.Millisecond, PacketSent: 1, PacketLost: 0, resultLock: &sync.Mutex{}}
	ip := &net.IPAddr{IP: net.ParseIP("172.217.161.14")}

	pingInfo := getPacketTimeExceededInfoText(pingResult, "del03s10-in-f14.1e100.net.", ip, 18, 0)
	correctPingInfo := "18 bytes from del03s10-in-f14.1e100.net. (172.217.161.14): packets_sent=1 packets_lost=0 ttl=0 ip time exceeded"

	assert.Equal(t, pingInfo, correctPingInfo)
}

func TestAddrType(t *testing.T) {
	var resolveHostname, resolveIP4, resolveIP6 AddrType

	hostname := "google.com"
	ip4 := "8.8.8.8"
	ip6 := "2404:6800:4002:809::200e"

	resolveHostname, _ = resolveAddrType(hostname)
	resolveIP4, _ = resolveAddrType(ip4)
	resolveIP6, _ = resolveAddrType(ip6)

	assert.Equal(t, resolveHostname, Hostname)
	assert.Equal(t, resolveIP4, IP4)
	assert.Equal(t, resolveIP6, IP6)
}

func TestGetICMPMessage(t *testing.T) {
	icmpID := 100
	seq := 1

	icmpMsgIP4 := &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   icmpID,
			Seq:  seq,
			Data: []byte(""),
		},
	}

	icmpMsgIP6 := &icmp.Message{
		Type: ipv6.ICMPTypeEchoRequest,
		Code: 0,
		Body: &icmp.Echo{
			ID:   icmpID,
			Seq:  seq,
			Data: []byte(""),
		},
	}

	ip4Msg := getICMPEchoMessage("ip4", icmpID, seq)
	ip6Msg := getICMPEchoMessage("ip6", icmpID, seq)

	assert.Equal(t, icmpMsgIP4, ip4Msg)
	assert.Equal(t, icmpMsgIP6, ip6Msg)
}

func TestICMPNetworkType(t *testing.T) {
	assert.Equal(t, "ip4", getNetworkType(IP4, false, false))
	assert.Equal(t, "ip4", getNetworkType(IP4, true, false))
	assert.Equal(t, "ip6", getNetworkType(IP6, false, true))
	assert.Equal(t, "ip6", getNetworkType(IP4, false, true))
	assert.Equal(t, "ip4", getNetworkType(IP4, true, true))
	assert.Equal(t, "ip4", getNetworkType(IP6, true, true))
	assert.Equal(t, "ip6", getNetworkType(IP6, false, false))
}

func TestGetICMPEndpoint(t *testing.T) {
	ip4Network := "ip4"
	ip6Network := "ip6"

	assert.Equal(t, ICMP6EndpointPrivileged, getICMPEndpoint(ip6Network, true))
	assert.Equal(t, ICMP4EndpointPrivileged, getICMPEndpoint(ip4Network, true))
	assert.Equal(t, ICMP6Endpoint, getICMPEndpoint(ip6Network, false))
	assert.Equal(t, ICMP4Endpoint, getICMPEndpoint(ip4Network, false))
}

func TestGetListenAddr(t *testing.T) {
	ip4Network := "ip4"
	ip6Network := "ip6"

	assert.Equal(t, ListenAddrIP6, getListenAddr(ip6Network))
	assert.Equal(t, ListenAddrIP4, getListenAddr(ip4Network))
}

func TestGetICMPProtocol(t *testing.T) {
	ip4Network := "ip4"
	ip6Network := "ip6"

	assert.Equal(t, ProtocolIPv6ICMP, getICMPProtocol(ip6Network))
	assert.Equal(t, ProtocolICMP4, getICMPProtocol(ip4Network))
}

func TestMsgTimeInjection(t *testing.T) {
	injectTime := time.Now()
	ip4Msg := getICMPEchoMessage("ip4", 100, 1)

	injectTimeInMsg(ip4Msg, injectTime)

	extractTime := getTimeFromMsg(ip4Msg)

	assert.Equal(t, injectTime.UnixNano(), extractTime.UnixNano())
}

func TestGetMsgBufWithNowTime(t *testing.T) {
	ip4Msg := getICMPEchoMessage("ip4", 100, 1)

	currTime := time.Now()
	buf, _, _ := getMsgBufWithNowTime(ip4Msg)

	msgParsed, _ := icmp.ParseMessage(1, buf)

	extractTime := getTimeFromMsg(msgParsed)

	// similar timings
	assert.Equal(t, currTime.Unix(), extractTime.Unix())
}
