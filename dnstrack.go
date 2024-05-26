package main

import (
	"os"
	"os/signal"
	"syscall"
)

// Options is the options set for the dnstrack instance.
type Options struct {
	// Server specifies the dns server filters
	Server string

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

func (dq *DnsTrack) Start() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, os.Interrupt)
	<-sigCh
}

func (dq *DnsTrack) Close() {
	dq.pcapClient.Close()
}
