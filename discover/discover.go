package discover

import (
	"fmt"
	"log"
	"maps"
	"net"
	"strconv"
	"strings"

	"github.com/hashicorp/mdns"
)


type DiscoveredType int
const DiscoveredTypeCommissioned = 1
const DiscoveredTypeCommissionable = 2

type DiscoveredDevice struct {
	Name string
	Host string
	Type DiscoveredType
	Addrs []net.IP
	PH string
	CM string
	VP string
	VendorId int
	ProductId int
	D string
	DN string
}

func (d DiscoveredDevice)Dump() {
	fmt.Printf("name: %s\n", d.Name)
	fmt.Printf("host: %s\n", d.Host)
	fmt.Printf("DN:   %s\n", d.DN)
	fmt.Printf("addreses: %v\n", d.Addrs)
	if d.Type != DiscoveredTypeCommissioned {
		fmt.Printf("PH: %s\n", d.PH)
		fmt.Printf("CM: %s\n", d.CM)
		fmt.Printf("VP: %s\n", d.VP)
		fmt.Printf("  vendor : %d\n", d.VendorId)
		fmt.Printf("  product: %d\n", d.ProductId)
		fmt.Printf("D: %s\n", d.D)
	}
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

func Discover(iface string) ([]DiscoveredDevice, error) {
	entriesCh := make(chan *mdns.ServiceEntry, 4)
	defer close(entriesCh)
	devices := []DiscoveredDevice{}
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
			dev := DiscoveredDevice {
				Name: entry.Name,
				Host: entry.Host,
				Addrs: addrs,
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
	return devices, nil
}

func Discover2(iface string, service string, disableipv6 bool) (map[string]DiscoveredDevice, error) {
	entriesCh := make(chan *mdns.ServiceEntry, 4)
	defer close(entriesCh)
	devices := map[string]DiscoveredDevice{}
	go func() {
    	for entry := range entriesCh {
			if !strings.Contains(entry.Name, service) {
				continue
			}
			addrs := []net.IP{}
			if entry.AddrV6 != nil {
				addrs = append(addrs, entry.AddrV6)
			}
			if entry.AddrV6 != nil {
				addrs = append(addrs, entry.AddrV4)
			}
			dev := DiscoveredDevice {
				Name: entry.Name,
				Host: entry.Host,
				Addrs: addrs,
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
			devices[entry.Host] = dev
    	}
	}()


	i, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	params := mdns.QueryParam {
		Service: service,
		Entries: entriesCh,
		DisableIPv6: disableipv6,
		Interface: i,
	}
	err = mdns.Query(&params)
	if err != nil {
		return nil, err
	}
	return devices, nil
}

func ListInterfaces(name string) []net.Interface {
	if len(name) != 0 {
		i, err := net.InterfaceByName(name)
		if err != nil {
			return []net.Interface{}
		}
		return []net.Interface{*i}
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return []net.Interface{}
	}
	return ifaces
}

func isEglible(iface net.Interface) bool {
	if iface.Flags & net.FlagRunning == 0 {
		return false
	}
	if iface.Flags & net.FlagLoopback != 0 {
		return false
	}
	if iface.Flags & net.FlagMulticast == 0 {
		return false
	}
	return true
}

func DiscoverAllComissioned(interfac string, disableipv6 bool) []DiscoveredDevice{
	ifaces := ListInterfaces(interfac)
	devices := map[string]DiscoveredDevice{}
	for _, iface := range ifaces {
		if !isEglible(iface) {
			continue
		}
		log.Printf("trying %v\n",iface)
		ds, _ := Discover2(iface.Name, "_matter._tcp", disableipv6)
		maps.Copy(devices, ds)
	}
	out := []DiscoveredDevice{}
	for _, d := range devices {
		d.Type = DiscoveredTypeCommissioned
		out = append(out, d)
	}
	return out
}


func DiscoverAllComissionable(interfac string, disableipv6 bool) []DiscoveredDevice{
	ifaces := ListInterfaces(interfac)
	devices := map[string]DiscoveredDevice{}
	for _, iface := range ifaces {
		if !isEglible(iface) {
			continue
		}
		log.Printf("trying %v\n",iface)
		ds, _ := Discover2(iface.Name, "_matterc._udp.", disableipv6)
		maps.Copy(devices, ds)
	}
	out := []DiscoveredDevice{}
	for _, d := range devices {
		d.Type = DiscoveredTypeCommissionable
		out = append(out, d)
	}
	return out
}
