//go:build !aix && !windows
// +build !aix,!windows

package pcap

import (
	"errors"
	"syscall"
	"unsafe"
)

func (p *pcapAddresses) next() bool {
	if p.cur == nil {
		p.cur = p.all
		if p.cur == nil {
			return false
		}
		return true
	}
	if p.cur.next == nil {
		return false
	}
	p.cur = p.cur.next
	return true
}

func (p pcapAddresses) addr() *syscall.RawSockaddr {
	return (*syscall.RawSockaddr)(unsafe.Pointer(p.cur.addr))
}

func (p pcapAddresses) netmask() *syscall.RawSockaddr {
	return (*syscall.RawSockaddr)(unsafe.Pointer(p.cur.netmask))
}

func (p pcapAddresses) broadaddr() *syscall.RawSockaddr {
	return (*syscall.RawSockaddr)(unsafe.Pointer(p.cur.broadaddr))
}

func (p pcapAddresses) dstaddr() *syscall.RawSockaddr {
	return (*syscall.RawSockaddr)(unsafe.Pointer(p.cur.dstaddr))
}

func findalladdresses(addresses pcapAddresses) (retval []InterfaceAddress) {
	// TODO - make it support more than IPv4 and IPv6?
	retval = make([]InterfaceAddress, 0, 1)
	for addresses.next() {
		// Strangely, it appears that in some cases, we get a pcap address back from
		// pcap_findalldevs with a nil .addr.  It appears that we can skip over
		// these.
		if addresses.addr() == nil {
			continue
		}
		var a InterfaceAddress
		var err error
		if a.IP, err = sockaddrToIP(addresses.addr()); err != nil {
			continue
		}
		// To be safe, we'll also check for netmask.
		if addresses.netmask() == nil {
			continue
		}
		if a.Netmask, err = sockaddrToIP(addresses.netmask()); err != nil {
			// If we got an IP address but we can't get a netmask, just return the IP
			// address.
			a.Netmask = nil
		}
		if a.Broadaddr, err = sockaddrToIP(addresses.broadaddr()); err != nil {
			a.Broadaddr = nil
		}
		if a.P2P, err = sockaddrToIP(addresses.dstaddr()); err != nil {
			a.P2P = nil
		}
		retval = append(retval, a)
	}
	return
}

func sockaddrToIP(rsa *syscall.RawSockaddr) (IP []byte, err error) {
	if rsa == nil {
		err = errors.New("Value not set")
		return
	}
	switch rsa.Family {
	case syscall.AF_INET:
		pp := (*syscall.RawSockaddrInet4)(unsafe.Pointer(rsa))
		IP = make([]byte, 4)
		for i := 0; i < len(IP); i++ {
			IP[i] = pp.Addr[i]
		}
		return
	case syscall.AF_INET6:
		pp := (*syscall.RawSockaddrInet6)(unsafe.Pointer(rsa))
		IP = make([]byte, 16)
		for i := 0; i < len(IP); i++ {
			IP[i] = pp.Addr[i]
		}
		return
	}
	err = errors.New("Unsupported address type")
	return
}
