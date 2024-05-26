//go:build !linux

package main

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/pkg/errors"

	"github.com/chenjiandongx/dnstrack/codec"
	"github.com/chenjiandongx/dnstrack/formatter"
)

type pcapHandler struct {
	device string
	handle *pcap.Handle
}

type PcapClient struct {
	opt        Options
	handlers   []*pcapHandler
	allDevices bool
	devices    string
	server     string
	cache      *cache
	formatter  formatter.Formatter
}

func NewPcapClient(opt Options) (*PcapClient, error) {
	client := &PcapClient{
		opt:        opt,
		devices:    opt.Devices,
		allDevices: opt.AllDevices,
		server:     opt.Server,
		cache:      newCache(),
		formatter:  formatter.New(opt.Format),
	}

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
		handler, err := c.getHandler(device.Name, bpfFilter)
		if err != nil {
			return errors.Wrapf(err, "get device(%s) name failed", device.Name)
		}

		c.handlers = append(c.handlers, &pcapHandler{
			device: device.Name,
			handle: handler,
		})
	}

	if len(c.handlers) == 0 {
		return errors.New("no available devices found")
	}

	return nil
}

func (c *PcapClient) getHandler(device, filter string) (*pcap.Handle, error) {
	handle, err := pcap.OpenLive(device, 65535, false, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return nil, err
	}

	return handle, nil
}

func (c *PcapClient) parsePacket(packet gopacket.Packet) *SP {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil
	}

	ipv4pkg := ipLayer.(*layers.IPv4)
	if ipv4pkg == nil {
		return nil
	}

	srcIP := ipv4pkg.SrcIP.String()
	dstIP := ipv4pkg.DstIP.String()

	layer := packet.Layer(layers.LayerTypeUDP)
	pkg, ok := layer.(*layers.UDP)
	if !ok {
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
	packetSource := gopacket.NewPacketSource(ph.handle, ph.handle.LinkType())
	packetSource.Lazy = true
	packetSource.NoCopy = true

	for {
		select {
		case packet, ok := <-packetSource.Packets():
			if !ok {
				return
			}
			sp := c.parsePacket(packet)
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
				c.cache.set(uk, packet.Metadata().Timestamp)
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
	for _, handler := range c.handlers {
		handler.handle.Close()
	}
}
