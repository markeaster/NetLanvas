//go:build windows

// tools/ping_sweep_helper/main.go
//
// NATIVE-2: Windows equivalent of pollers/ping_sweeper.py's fping call.
// No vetted third-party Windows fping port exists (same reasoning as
// WIN-9's snmp_helper -- see that tool's own header comment for why a
// purpose-built binary beats an unverified third-party one). Uses
// IcmpSendEcho directly via iphlpapi.dll -- the same non-privileged
// mechanism ping.exe itself uses on Windows. Confirmed against
// Microsoft's own IcmpCreateFile/IcmpSendEcho documentation, which
// states no elevation requirement anywhere, unlike a raw-socket ICMP
// approach (which Windows restricts to administrators, and which
// golang.org/x/net/icmp's own unprivileged datagram mode doesn't
// support on Windows at all -- confirmed before writing this, that
// mode is Darwin/Linux only).
//
// Deliberately Windows-only (the build tag above) -- Linux/macOS keep
// using the existing `fping` binary, already installed and proven
// there; this only ever ships in the Windows build.
//
// Output contract matches pollers/ping_sweeper.py's fping_sweep():
// one responding IP per stdout line, nothing else. Exits 0 whether or
// not any host responded -- an empty sweep of an idle subnet isn't an
// error condition.
package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"unsafe"
)

var (
	iphlpapi         = syscall.NewLazyDLL("iphlpapi.dll")
	procIcmpCreate   = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpClose    = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho = iphlpapi.NewProc("IcmpSendEcho")
)

const (
	requestTimeoutMs = 200 // matches fping's -t 200 on the Linux path
	requestPayload   = "netlanvas-ping-sweep"
	workerCount      = 64

	// ICMP_ECHO_REPLY32 (the 64-bit-process reply layout IcmpSendEcho
	// actually fills, per ipexport.h -- confirmed against Microsoft's
	// docs before writing this, since guessing the wrong struct here
	// would silently misparse every reply) is 4(Address)+4(Status)+
	// 4(RoundTripTime)+2(DataSize)+2(Reserved)+4(Data, a POINTER_32
	// even in a 64-bit process)+IP_OPTION_INFORMATION32's own few
	// bytes, plus the echoed request payload, plus 8 bytes Microsoft's
	// docs say to reserve for a possible ICMP error message. 256 bytes
	// comfortably covers all of that for this tool's tiny payload --
	// only the first 8 bytes (Address, Status) are actually parsed.
	replyBufSize = 256
)

func pingOnce(handle uintptr, ipv4 uint32) bool {
	reply := make([]byte, replyBufSize)
	payload := []byte(requestPayload)

	ret, _, _ := procIcmpSendEcho.Call(
		handle,
		uintptr(ipv4),
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(len(payload)),
		0, // no IP header options
		uintptr(unsafe.Pointer(&reply[0])),
		uintptr(len(reply)),
		uintptr(requestTimeoutMs),
	)
	if ret == 0 {
		return false
	}
	status := binary.LittleEndian.Uint32(reply[4:8])
	return status == 0 // IP_SUCCESS
}

// IcmpSendEcho's DestinationAddress is an IPAddr -- a DWORD holding
// the 4 address octets in the same byte order inet_addr() produces,
// i.e. the first octet occupies the DWORD's low byte. Reading the
// 4 octets as a little-endian uint32 reproduces exactly that value
// on every real (little-endian) Windows target.
func ipToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	return binary.LittleEndian.Uint32(ip4)
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func hostsInCIDR(cidr string) ([]net.IP, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incIP(ip) {
		dup := make(net.IP, len(ip))
		copy(dup, ip)
		ips = append(ips, dup)
	}
	// Drop network/broadcast addresses -- matches fping -g's own
	// behavior on a CIDR argument. Left alone for /31 and smaller
	// (nothing to drop without emptying the list).
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}
	return ips, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: netlanvas_ping_sweep <subnet-cidr>")
		os.Exit(2)
	}

	ips, err := hostsInCIDR(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid subnet %q: %v\n", os.Args[1], err)
		os.Exit(2)
	}

	jobs := make(chan net.IP, len(ips))
	for _, ip := range ips {
		jobs <- ip
	}
	close(jobs)

	var mu sync.Mutex
	var alive []string
	var wg sync.WaitGroup

	n := workerCount
	if len(ips) < n {
		n = len(ips)
	}
	for w := 0; w < n; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			handle, _, _ := procIcmpCreate.Call()
			if handle == 0 || handle == ^uintptr(0) {
				return // INVALID_HANDLE_VALUE -- this worker contributes nothing
			}
			defer procIcmpClose.Call(handle)

			for ip := range jobs {
				if pingOnce(handle, ipToUint32(ip)) {
					mu.Lock()
					alive = append(alive, ip.String())
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()

	for _, ip := range alive {
		fmt.Println(ip)
	}
}
