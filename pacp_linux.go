//go:build linux

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/pkg/errors"
	"golang.org/x/net/bpf"

	"github.com/chenjiandongx/dnstrack/codec"
	"github.com/chenjiandongx/dnstrack/formatter"
)

type pcapHandler struct {
	device string
	handle *afpacket.TPacket
}

type PcapClient struct {
	ctx        context.Context
	cancel     context.CancelFunc
	handlers   []*pcapHandler
	devices    string
	server     string
	allDevices bool
	cache      *cache
	formatter  formatter.Formatter
}

func NewPcapClient(opt Options) (*PcapClient, error) {
	client := &PcapClient{
		devices:    opt.Devices,
		allDevices: opt.AllDevices,
		formatter:  formatter.New(opt.Format),
		server:     opt.Server,
		cache:      newCache(),
	}

	client.ctx, client.cancel = context.WithCancel(context.Background())
	if err := client.getAvailableDevices(); err != nil {
		return nil, err
	}

	for _, handler := range client.handlers {
		go client.listen(handler)
	}

	return client, nil
}

func (c *PcapClient) getAvailableDevices() error {
	devs, err := filterDevices(c.devices, c.allDevices)
	if err != nil {
		return err
	}

	for _, device := range devs {
		handler, err := c.getHandler(device.Name)
		if err != nil {
			return errors.Wrapf(err, "get device(%s) name failed", device.Name)
		}

		if err = c.setBPFFilter(handler, bpfFilter); err != nil {
			return errors.Wrapf(err, "set bpf-filter on device(%s) failed", device.Name)
		}
		c.handlers = append(c.handlers, &pcapHandler{device: device.Name, handle: handler})
	}

	if len(c.handlers) == 0 {
		return errors.New("no available devices found")
	}
	return nil
}

func (c *PcapClient) getHandler(device string) (*afpacket.TPacket, error) {
	return afpacket.NewTPacket(afpacket.OptInterface(device))
}

func (c *PcapClient) setBPFFilter(h *afpacket.TPacket, filter string) error {
	pcapBPF, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, 65535, filter)
	if err != nil {
		return err
	}
	var bpfIns []bpf.RawInstruction
	for _, ins := range pcapBPF {
		bpfIns = append(bpfIns, bpf.RawInstruction{
			Op: ins.Code,
			Jt: ins.Jt,
			Jf: ins.Jf,
			K:  ins.K,
		})
	}
	return h.SetBPF(bpfIns)
}

func (c *PcapClient) parsePacket(data []byte) *SP {
	var ether layers.Ethernet
	var err error
	if err = ether.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
		return nil
	}

	switch ether.EthernetType {
	case layers.EthernetTypeIPv4, layers.EthernetTypeIPv6:
	default:
		return nil
	}

	var ipv4 layers.IPv4
	if err = ipv4.DecodeFromBytes(ether.Payload, gopacket.NilDecodeFeedback); err != nil {
		return nil
	}

	srcIP := ipv4.SrcIP.String()
	dstIP := ipv4.DstIP.String()
	var pkg layers.UDP
	if err = pkg.DecodeFromBytes(ipv4.Payload, gopacket.NilDecodeFeedback); err != nil {
		return nil
	}

	srcPort := uint16(pkg.SrcPort)
	dstPort := uint16(pkg.DstPort)

	var server string
	if srcPort == dnsPort {
		server = fmt.Sprintf("%s:%d", srcIP, srcPort)
	} else {
		server = fmt.Sprintf("%s:%d", dstIP, dstPort)
	}
	if c.server != "" && c.server+":53" != server {
		return nil
	}

	return &SP{
		Server:  server,
		Payload: pkg.Payload,
	}
}

func (c *PcapClient) listen(ph *pcapHandler) {
	for {
		select {
		case <-c.ctx.Done():
			return

			// decode packets followed by layers
			// 1) Ethernet Layer
			// 2) IP Layer
			// 3) UDP Layer
		default:
			pkt, _, err := ph.handle.ZeroCopyReadPacketData()
			if err != nil {
				continue
			}
			sp := c.parsePacket(pkt)
			if sp == nil {
				continue
			}

			r, err := codec.Decode(sp.Payload)
			if err != nil {
				continue
			}

			header := r.Header
			uk := fmt.Sprintf("%s/%d", ph.device, header.ID)
			if !header.Response {
				c.cache.set(uk, time.Now()) // approximate time
				continue
			}
			t, ok := c.cache.get(uk)
			if !ok {
				continue
			}

			fmt.Println(c.formatter.Format(formatter.MessageWrap{
				Duration: time.Since(t),
				Msg:      r,
				Device:   ph.device,
				Server:   sp.Server,
			}))
		}
	}
}

func (c *PcapClient) Close() {
	c.cancel()
	for _, handler := range c.handlers {
		handler.handle.Close()
	}
}
