package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

// Options is the options set for the dnstrack instance.
type Options struct {
	// Server specifies the dns server filters
	Server string

	// Type specifies the dns query type, optional:
	// A/AAAA/CNAME/NS/PTR/...
	Type string

	// Devices represents devices regexp pattern to monitor
	Devices string

	// AllDevices specifies whether to listen all devices or not
	AllDevices bool

	// Format decides to output format, optional:
	// - json/j
	// - yaml/y
	// - question/q
	// - verbose/v
	Format string
}

func DefaultOptions() Options {
	return Options{
		AllDevices: true,
		Format:     "verbose",
	}
}

type DnsTrack struct {
	opts       Options
	pcapClient *PcapClient
}

func NewDnsTrack(opts Options) (*DnsTrack, error) {
	pcapClient, err := NewPcapClient(opts)
	if err != nil {
		return nil, err
	}

	return &DnsTrack{
		opts:       opts,
		pcapClient: pcapClient,
	}, nil
}

func (dt *DnsTrack) Start() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, os.Interrupt)
	<-sigCh
}

func (dt *DnsTrack) Close() {
	stats := dt.pcapClient.Stats()
	fmt.Fprintf(os.Stderr, "\n%d queries captured\n%d queries dropped by filter\n%d queries no response\n", stats.Queries, stats.Drop, stats.Missing)
	dt.pcapClient.Close()
}
