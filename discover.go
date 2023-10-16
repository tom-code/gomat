package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/hashicorp/mdns"
)


type Device struct {
	name string
	host string
	addrs []net.IP
	PH string
	CM string
	VP string
	VendorId int
	ProductId int
	D string
	DN string
}

func (d Device)Dump() {
	fmt.Printf("name: %s\n", d.name)
	fmt.Printf("host: %s\n", d.host)
	fmt.Printf("DN:   %s\n", d.DN)
	fmt.Printf("addrs: %v\n", d.addrs)
	fmt.Printf("PH: %s\n", d.PH)
	fmt.Printf("CM: %s\n", d.CM)
	fmt.Printf("VP: %s\n", d.VP)
	fmt.Printf("  vendor : %d\n", d.VendorId)
	fmt.Printf("  product: %d\n", d.ProductId)
	fmt.Printf("D: %s\n", d.D)
}

func parseVP(vp string) (int, int) {
	s := strings.Split(vp, "+")
	vid, err := strconv.Atoi(s[0])
	if err != nil {
		return -1, -1
	}
	pid := -1
	if len(s) == 2 {
		pid, _ = strconv.Atoi(s[1])
	}
	return vid, pid
}

func discover(iface string) ([]Device, error) {
	entriesCh := make(chan *mdns.ServiceEntry, 4)
	defer close(entriesCh)
	devices := []Device{}
	go func() {
    	for entry := range entriesCh {
        	fmt.Printf("Got new entry: %+v\n", entry)
			if !strings.Contains(entry.Name, "_matterc") {
				continue
			}
			addrs := []net.IP{}
			if entry.AddrV6 != nil {
				addrs = append(addrs, entry.AddrV6)
			}
			if entry.AddrV6 != nil {
				addrs = append(addrs, entry.AddrV4)
			}
			dev := Device {
				name: entry.Name,
				host: entry.Host,
				addrs: addrs,
			}
			for _, s := range entry.InfoFields {
				if strings.HasPrefix(s, "PH=") {
					dev.PH = s[3:]
				}
				if strings.HasPrefix(s, "CM=") {
					dev.CM = s[3:]
				}
				if strings.HasPrefix(s, "VP=") {
					dev.VP = s[3:]
					dev.VendorId, dev.ProductId = parseVP(dev.VP)
				}
				if strings.HasPrefix(s, "D=") {
					dev.D = s[2:]
				}
				if strings.HasPrefix(s, "DN=") {
					dev.DN = s[3:]
				}
			}
			devices = append(devices, dev)
    	}
	}()


	i, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	params := mdns.QueryParam {
		Service: "_matterc._udp.",
		Entries: entriesCh,
		DisableIPv6: true,
		Interface: i,
	}
	err = mdns.Query(&params)
	if err != nil {
		panic(err)
	}
	//time.Sleep(3*time.Second)
	//close(entriesCh)
	return devices, nil
}

