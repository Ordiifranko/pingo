package main

import (
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"os/signal"
	"syscall"
	"time"

	Log "github.com/arush15june/ping/pkg/logger"
	Pinger "github.com/arush15june/ping/pkg/pinger"
)

var (
	start time.Time
)

// Arguments
var (
	// Verbose enables printing verbose logs.
	Verbose bool

	// TargetName is a positional argument, it stores the value of the IP destination.
	// Can be hostname, IPv4, IPv6.
	TargetName string

	// ForceIP4 flag forces IPv4 usage.
	ForceIP4 bool

	// ForceIP6 flag forces IPv6 usage.
	ForceIP6 bool

	// Count flag stores the number of ECHO datagrams to send.
	Count int

	// Timeout flag stores the request timeout.
	Timeout time.Duration

	// Interval is the time between sending packets.
	Interval time.Duration

	// Flood enables flood mode where a sent packet is a . character
	// and a received packet is a backspace character.
	Flood bool

	// Privileged flag allows selecting between UDP ping or Raw ICMP Ping (requires superuser permissions).
	Privilege bool

	// TTL flag stores IP TTL field value.
	TTL int

	// AllowTTL flag allows storing TTL values in IP Header.
	AllowTTL bool
)

// Usage overrides default flag.Usage
// This usage does not contain executable name in the usage.
var Usage = func() {
	fmt.Println()
	fmt.Fprintf(flag.CommandLine.Output(), "Usage: \n")
	flag.PrintDefaults()
}

const (
	DefaultVerbose   = false
	DefaultForceIP4  = false
	DefaultForceIP6  = false
	DefaultFlood     = false
	DefaultCount     = 0
	DefaultTimeout   = 2 * time.Second
	DefaultInterval  = 1000 * time.Millisecond
	DefaultTTL       = -1
	DefaultAllowTTL  = false
	DefaultPrivilege = true
)

// initFlags defines the flags, parses them and binds them to the correpsonding global vars.
func initFlags() error {
	flag.BoolVar(&Verbose, "v", DefaultVerbose, "Verbose logging.")
	flag.BoolVar(&ForceIP4, "4", DefaultForceIP4, "Use IPv4 only.")
	flag.BoolVar(&ForceIP6, "6", DefaultForceIP6, "Use IPv6 only.")
	flag.BoolVar(&Flood, "f", DefaultFlood, "Flood mode.")
	flag.BoolVar(&Privilege, "priv", DefaultPrivilege, "Raw ICMP Packet or UDP Ping.")
	flag.IntVar(&Count, "c", DefaultCount, "Number of Echo Request's to send.")
	flag.DurationVar(&Timeout, "W", DefaultTimeout, "Time for sent echo request to timeout.")
	flag.DurationVar(&Interval, "i", DefaultInterval, "Wait interval between sending packets.")
	flag.IntVar(&TTL, "t", DefaultTTL, "IP Time to Live. Use with -T.")
	flag.BoolVar(&AllowTTL, "T", DefaultAllowTTL, "Alow IP TTL.")

	flag.Parse()
	if flag.NArg() == 0 {
		return errors.New("target not found.")
	}

	// Get argument left after processing flags i.e target destination.
	TargetName = flag.Arg(0)

	flag.Usage = Usage

	return nil
}

func signalHandler(pinger *Pinger.PingConfig, sig_chan chan os.Signal) {
	<-sig_chan
	prinPingResults(pinger)
	os.Exit(0)
}

// getStdDevRTT returns the standard deviation from the mean
// computed over the RTT of all packets.
func getStdDevRTT(pinger *Pinger.PingConfig) time.Duration {
	if len(pinger.Result.RTT) == 0 {
		return time.Duration(0) * time.Nanosecond
	}

	var stdDevNano float64
	avgRTTNano := float64(pinger.Result.AvgRTT.Nanoseconds())

	for _, rtt := range pinger.Result.RTT {
		stdDevNano += math.Pow(
			float64(rtt.Nanoseconds())-avgRTTNano,
			2,
		)
	}

	stdDevNano = math.Sqrt(stdDevNano / float64(pinger.Result.PacketRecvd))

	return time.Duration(int(stdDevNano)) * time.Nanosecond
}

// Print statistics of the ping execution.
func prinPingResults(pinger *Pinger.PingConfig) {
	// 100% default packet loss, i.e no packet was received.
	var packetLossRatio float64 = 100.0
	if pinger.Result.PacketLost > 0 {
		packetLossRatio = (float64(pinger.Result.PacketLost)/float64(pinger.Result.PacketSent)) * 100
	}

	stdDev := getStdDevRTT(pinger)

	fmt.Printf("\n")
	fmt.Printf("----------- %s (%s) ping statistics -----------\n", pinger.Lookup, pinger.Target)
	fmt.Printf(
		"%d packets transmitted, %d received, %.2f percent packet loss\n",
		pinger.Result.PacketSent,
		pinger.Result.PacketRecvd,
		packetLossRatio,
	)
	fmt.Printf(
		"rtt avg/mix/max/stddev = %v/%v/%v/%v\n",
		pinger.Result.AvgRTT,
		pinger.Result.MinRTT,
		pinger.Result.MaxRTT,
		stdDev,
	)
}

func main() {
	err := initFlags()
	if err != nil {
		fmt.Println("Error: ", err)
		flag.Usage()
		os.Exit(1)
	}

	Log.SetVerbose(Verbose)
	Log.InitLogger(os.Stdout, os.Stdout)

	Log.Debugln("Destination: ", TargetName)

	pinger := Pinger.NewPing(
		TargetName,
		ForceIP4,
		ForceIP6,
		Count,
		Timeout,
		TTL,
		AllowTTL,
		Interval,
		Flood,
		Privilege,
	)

	signal_chan := make(chan os.Signal, 1)
	signal.Notify(signal_chan,
		syscall.SIGINT,
	)
	go signalHandler(pinger, signal_chan)

	start = time.Now()
	_, err = pinger.Ping()
	if err != nil {
		fmt.Println("failure:", err)
		flag.Usage()
		os.Exit(1)
	}
	prinPingResults(pinger)
}
