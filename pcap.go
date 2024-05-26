package main

import (
	"regexp"

	"github.com/google/gopacket/pcap"
)

const (
	dnsPort   = 53
	bpfFilter = "udp and port 53"
)

type SP struct {
	Server  string
	Payload []byte
}

func ListAllDevices() ([]pcap.Interface, error) {
	return pcap.FindAllDevs()
}

func filterDevices(devices string, allowAll bool) ([]pcap.Interface, error) {
	all, err := ListAllDevices()
	if err != nil {
		return nil, err
	}

	var r *regexp.Regexp
	if len(devices) > 0 {
		r, err = regexp.Compile(devices)
		if err != nil {
			return nil, err
		}
	}

	var devs []pcap.Interface
	for _, device := range all {
		if r != nil {
			if r.MatchString(device.Name) {
				devs = append(devs, device)
			}
		} else {
			if allowAll {
				devs = append(devs, device)
			}
		}
	}

	return devs, nil
}
