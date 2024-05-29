package main

import (
	"fmt"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/google/gopacket/pcap"

	"github.com/chenjiandongx/dnstrack/codec"
	"github.com/chenjiandongx/dnstrack/formatter"
)

const (
	dnsPort   = 53
	bpfFilter = "udp and port 53"
)

type SP struct {
	Server  string
	Payload []byte
}

type Stats struct {
	Queries int64
	Drop    int64
	Missing int64
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

type CommonClient struct {
	cache *cache
	f     formatter.Formatter

	queries  atomic.Int64
	dropped  atomic.Int64
	response atomic.Int64
}

func NewCommonClient(f formatter.Formatter) *CommonClient {
	return &CommonClient{
		cache: newCache(),
		f:     f,
	}
}

func (c *CommonClient) Display(sp *SP, device string, ts time.Time) {
	size := len(sp.Payload)
	r, err := codec.Decode(sp.Payload)
	if err != nil {
		return
	}

	header := r.Header
	uk := fmt.Sprintf("%s/%d", device, header.ID)
	if !header.Response {
		c.queries.Add(1)
		c.cache.set(uk, ts)
		return
	}
	t, ok := c.cache.get(uk)
	if !ok {
		return
	}

	s, ok := c.f.Format(formatter.MessageWrap{
		When:     t,
		Size:     size,
		Duration: time.Since(t),
		Msg:      r,
		Device:   device,
		Server:   sp.Server,
	})
	if ok {
		c.response.Add(1)
		fmt.Println(s)
	} else {
		c.dropped.Add(1)
	}
}

func (c *CommonClient) Stats() Stats {
	queries := c.queries.Load()
	dropped := c.dropped.Load()
	missing := queries - c.response.Load()
	return Stats{
		Queries: queries,
		Drop:    dropped,
		Missing: missing,
	}
}
