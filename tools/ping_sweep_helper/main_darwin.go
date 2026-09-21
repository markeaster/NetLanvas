//go:build darwin

// tools/ping_sweep_helper/main_darwin.go
//
// NATIVE-10: macOS equivalent of main.go's Windows IcmpSendEcho tool.
// The header comment on that file said "Linux/macOS keep using the
// existing fping binary" -- true for Linux (fping is a standard
// package there), but NOT true for a real native macOS install: fping
// isn't part of base macOS, only available via Homebrew, and this
// project's own standing rule (see main.go's own header, and WIN-9's
// snmp_helper) is a purpose-built binary over an unverified/optional
// third-party dependency an installer would otherwise have to demand
// the user pre-install themselves.
//
// Uses golang.org/x/net/icmp's "udp4" mode -- macOS's/the BSD kernel's
// unprivileged ICMP datagram-socket path, confirmed working live on
// real Apple Silicon hardware (Phase 6.0 de-risk spike, 2026-09-02)
// with no root/sudo needed, unlike a raw ICMP socket. Same non-
// privileged bar as Windows' IcmpSendEcho and Linux's fping (which
// also uses this same mechanism when available, falling back to
// raw sockets + setuid otherwise on Linux distros too old to have it).
//
// Output contract matches pollers/ping_sweeper.py's fping_sweep():
// one responding IP per stdout line, nothing else. Exits 0 whether or
// not any host responded -- an empty sweep of an idle subnet isn't an
// error condition. hostsInCIDR/incIP are identical to main.go's --
// duplicated rather than shared because the two files never compile
// together (mutually exclusive //go:build tags), and a shared third
// file for two ~10-line functions wasn't worth the indirection.
package main

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	requestTimeout = 200 * time.Millisecond // matches fping's -t 200 on Linux
	workerCount    = 64
)

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
	// behavior on a CIDR argument. Left alone for /31 and smaller.
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}
	return ips, nil
}

// Each worker opens its OWN unprivileged ICMP socket AND uses its own
// distinct ICMP identifier (echoID below) -- NOT one shared socket
// read by many goroutines, and NOT the whole process's shared PID as
// the ID. Both were tried and both failed, confirmed live against
// real hardware (2026-09-02): a shared socket lets concurrent
// ReadFrom() calls each receive whichever reply arrives next
// regardless of which worker's request it actually answers, and using
// os.Getpid() as the ID -- reasonable-looking, since that's the
// classic single-threaded ping-tool pattern -- means EVERY worker's
// request carries the IDENTICAL id, since they all run in the same
// process. macOS's unprivileged-ICMP delivery, it turns out, doesn't
// demux purely per-socket the way a UDP port would: multiple sockets
// sharing one echo ID can all end up handed copies of whichever single
// reply arrives, not specifically the one matching what THAT socket
// sent -- confirmed live via a debug build: every one of 64 concurrent
// workers reported the SAME peer address back (the first real
// responder), 63 of them wrongly, only the one actually sweeping that
// exact IP giving a "correct" result by coincidence. A unique ID per
// worker, and validating the reply's OWN echo ID field (not just
// trusting the reported source address) is the fix -- the ICMP ID
// field exists specifically so multiple concurrent probes from one
// host CAN be told apart; per-worker sockets alone weren't sufficient
// for that on this platform.
func pingSweep(ips []net.IP) []string {
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
		go func(workerID int) {
			defer wg.Done()
			conn, err := icmp.ListenPacket("udp4", "0.0.0.0")
			if err != nil {
				return // this worker contributes nothing
			}
			defer conn.Close()

			// Distinct per worker, stable across every job that worker
			// processes -- 16 bits total (the ICMP echo ID field's own
			// width), workerCount (64) comfortably fits in the low byte
			// alongside a process-derived high byte so two concurrent
			// invocations of this tool don't collide with each other either.
			echoID := ((os.Getpid() & 0xff) << 8) | (workerID & 0xff)

			for ip := range jobs {
				if pingOnce(conn, ip, echoID) {
					mu.Lock()
					alive = append(alive, ip.String())
					mu.Unlock()
				}
			}
		}(w)
	}
	wg.Wait()
	return alive
}

func pingOnce(conn *icmp.PacketConn, ip net.IP, echoID int) bool {
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{ID: echoID, Seq: 1, Data: []byte("netlanvas")},
	}
	wb, err := msg.Marshal(nil)
	if err != nil {
		return false
	}
	if _, err := conn.WriteTo(wb, &net.UDPAddr{IP: ip}); err != nil {
		return false
	}

	deadline := time.Now().Add(requestTimeout)
	rb := make([]byte, 512)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false
		}
		conn.SetReadDeadline(time.Now().Add(remaining))
		n, peer, err := conn.ReadFrom(rb)
		if err != nil {
			return false // timeout
		}
		udpAddr, ok := peer.(*net.UDPAddr)
		if !ok || !udpAddr.IP.Equal(ip) {
			continue // not this worker's target -- macOS can hand a socket a reply meant for a different one, see pingSweep's comment; keep waiting out the remaining deadline rather than giving up on the first mismatch
		}
		rm, err := icmp.ParseMessage(1, rb[:n])
		if err != nil {
			continue
		}
		echo, ok := rm.Body.(*icmp.Echo)
		if !ok || echo.ID != echoID {
			continue // source IP matched, but this is still someone else's reply (shared-ID delivery) -- the ID field is the real correlation, not source address alone
		}
		return rm.Type == ipv4.ICMPTypeEchoReply
	}
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

	for _, ip := range pingSweep(ips) {
		fmt.Println(ip)
	}
}
