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

	"github.com/chenjiandongx/dnstrack/formatter"
)

type pcapHandler struct {
	device string
	handle *afpacket.TPacket
}

type PcapClient struct {
	ctx         context.Context
	cancel      context.CancelFunc
	opt         Options
	handlers    []*pcapHandler
	common      *CommonClient
	maxIfaceLen int
}

func NewPcapClient(opt Options) (*PcapClient, error) {
	client := &PcapClient{opt: opt}
	client.ctx, client.cancel = context.WithCancel(context.Background())
	if err := client.getAvailableDevices(); err != nil {
		return nil, err
	}

	client.common = NewCommonClient(formatter.New(opt.Format, opt.Server, opt.Type, client.maxIfaceLen))
	for _, handler := range client.handlers {
		go client.listen(handler)
	}

	return client, nil
}

func (c *PcapClient) getAvailableDevices() error {
	devs, err := filterDevices(c.opt.Devices, c.opt.AllDevices)
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

		if c.maxIfaceLen < len(device.Name) {
			c.maxIfaceLen = len(device.Name)
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
			c.common.Display(sp, ph.device, time.Now()) // approximate time
		}
	}
}

func (c *PcapClient) Stats() Stats {
	return c.common.Stats()
}

func (c *PcapClient) Close() {
	c.cancel()
	for _, handler := range c.handlers {
		handler.handle.Close()
	}
}
