//go:build aix
// +build aix

package pcap

func findalladdresses(addresses pcapAddresses) (retval []InterfaceAddress) {
	// TODO - make it support more than IPv4 and IPv6?
	retval = make([]InterfaceAddress, 0, 1)
	return
}
