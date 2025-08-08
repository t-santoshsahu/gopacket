//go:build aix
// +build aix

package pcap

import (
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"os"
	"time"
)

func pcapGetTstampPrecision(cptr pcapTPtr) int {
	return 0
}

func pcapOpenLive(device string, snaplen int, pro int, timeout int) (*Handle, error) {
	return &Handle{}, nil
}

func openOffline(file string) (handle *Handle, err error) {
	return &Handle{}, nil
}
func (p *Handle) pcapClose() {
}

func (p *Handle) pcapGeterr() error {
	return nil
}

func (p *Handle) pcapStats() (*Stats, error) {
	return &Stats{}, nil
}

func (p *Handle) pcapCompile(expr string, maskp uint32) (pcapBpfProgram, error) {
	return pcapBpfProgram{}, nil
}

func (p pcapBpfProgram) free() {
}

func (p pcapBpfProgram) toBPFInstruction() []BPFInstruction {
	bpfInstruction := make([]BPFInstruction, 0)
	return bpfInstruction
}

func (p *Handle) pcapSetfilter(bpf pcapBpfProgram) error {
	return nil
}

func (p *Handle) pcapListDatalinks() (datalinks []Datalink, err error) {
	datalinks = make([]Datalink, 0)
	return datalinks, nil
}

func pcapOpenDead(linkType layers.LinkType, captureLength int) (*Handle, error) {
	return &Handle{}, nil
}

func (p *Handle) pcapNextPacketEx() NextError {
	return NextError(0)
}

func (p *Handle) pcapDatalink() layers.LinkType {
	return layers.LinkType(layers.LinkTypeEthernet)
}

func (p *Handle) pcapSetDatalink(dlt layers.LinkType) error {
	return nil
}

func pcapDatalinkValToName(dlt int) string {
	return ""
}

func pcapDatalinkValToDescription(dlt int) string {
	return ""
}

func pcapDatalinkNameToVal(name string) int {
	return 0
}

func pcapLibVersion() string {
	return ""
}

func (p *Handle) isOpen() bool {
	return true
}

func (p *Handle) pcapSendpacket(data []byte) error {
	return nil
}

func (p *Handle) pcapSetdirection(direction Direction) error {
	return nil
}

func (p *Handle) pcapSnapshot() int {
	return 0
}

func (t TimestampSource) pcapTstampTypeValToName() string {
	return ""
}

func pcapTstampTypeNameToVal(s string) (TimestampSource, error) {
	return TimestampSource(0), nil
}

func (p *InactiveHandle) pcapGeterr() error {
	return nil
}

func (p *InactiveHandle) pcapActivate() (*Handle, activateError) {
	return &Handle{}, 0
}

func (p *InactiveHandle) pcapClose() {
}

func pcapCreate(device string) (*InactiveHandle, error) {
	return &InactiveHandle{}, nil
}

func (p *InactiveHandle) pcapSetSnaplen(snaplen int) error {
	return nil
}

func (p *InactiveHandle) pcapSetPromisc(promisc bool) error {
	return nil
}

func (p *InactiveHandle) pcapSetTimeout(timeout time.Duration) error {
	return nil
}

func (p *InactiveHandle) pcapListTstampTypes() (out []TimestampSource) {
	return
}

func (p *InactiveHandle) pcapSetTstampType(t TimestampSource) error {
	return nil
}

func (p *InactiveHandle) pcapSetRfmon(monitor bool) error {
	return nil
}

func (p *InactiveHandle) pcapSetBufferSize(bufferSize int) error {
	return nil
}

func (p *InactiveHandle) pcapSetImmediateMode(mode bool) error {
	return nil
}

func (p *Handle) setNonBlocking() error {
	return nil
}

// waitForPacket waits for a packet or for the timeout to expire.
func (p *Handle) waitForPacket() {
}

// openOfflineFile returns contents of input file as a *Handle.
func openOfflineFile(file *os.File) (handle *Handle, err error) {
	return &Handle{}, nil
}

func (h *pcapPkthdr) getSec() int64 {
	return 0
}

func (h *pcapPkthdr) getUsec() int64 {
	return 0
}

func (h *pcapPkthdr) getLen() int {
	return 0
}

func (h *pcapPkthdr) getCaplen() int {
	return 0
}

func pcapLookupnet(device string) (netp, maskp uint32, err error) {
	return
}

func pcapBpfProgramFromInstructions(bpfInstructions []BPFInstruction) pcapBpfProgram {
	return pcapBpfProgram{}
}

func (b *BPF) pcapOfflineFilter(ci gopacket.CaptureInfo, data []byte) bool {
	return true
}

type pcapDevices struct {
	all, cur *pcapIf
}

func (p pcapDevices) free() {
}

func (p *pcapDevices) next() bool {
	return false
}

func (p pcapDevices) name() string {
	return ""
}

func (p pcapDevices) description() string {
	return ""
}

func (p pcapDevices) flags() uint32 {
	return p.cur.Flags
}

type pcapAddresses struct {
	all, cur *pcapAddr
}

func (p *pcapAddresses) next() bool {
	return false
}

func (p pcapAddresses) addr() interface{} {
	return nil
}

func (p pcapAddresses) netmask() interface{} {
	return nil
}

func (p pcapAddresses) broadaddr() interface{} {
	return nil
}

func (p pcapAddresses) dstaddr() interface{} {
	return nil
}

func (p pcapDevices) addresses() pcapAddresses {
	return pcapAddresses{all: p.cur.Addresses}
}

func pcapFindAllDevs() (pcapDevices, error) {
	return pcapDevices{}, nil
}

func pcapSetTstampPrecision(cptr pcapTPtr, precision int) error {
	return nil
}

func findalladdresses(addresses pcapAddresses) (retval []InterfaceAddress) {
	// TODO - make it support more than IPv4 and IPv6?
	retval = make([]InterfaceAddress, 0, 1)
	return
}
