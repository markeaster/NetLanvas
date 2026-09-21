// tools/snmp_helper/main.go
//
// NATIVE-3: Windows has no net-snmp CLI (no winget/Chocolatey package,
// Net-SNMP itself only ships Windows source, not a binary -- same
// research finding WIN-9's proof-of-concept helper documented). This
// is the production replacement for engine/snmp_adapter.py's
// run_snmp_command(), which shells out to snmpget/snmpwalk on Linux/
// macOS -- gosnmp (already a dependency of the WIN-9 proof-of-concept
// at tools/platform_readiness_check/snmp_helper) gives GET/WALK plus
// full v2c/v3 (authPriv) support with no C toolchain needed to
// cross-compile.
//
// Security (F10/F14, see security-finding-patterns): credentials
// never go on argv, where any co-resident local process/user can read
// them for the call's lifetime via a process listing -- exactly the
// same reasoning run_snmp_command() already applies on Linux (a
// private mode-0600 snmp.conf instead of -c/-u/-A/-X flags). Here the
// credential is read once from stdin as JSON instead; only the
// non-secret parameters (ip, oid, get/walk, timeout, retries) are argv.
//
// Output contract matches run_snmp_command()'s expectation of raw
// net-snmp `-On -Oq` text exactly (confirmed empirically against a
// real local snmpd before writing this, not assumed): each result
// line is "<numeric-OID> <value>", OCTET STRING values double-quoted,
// everything else printed bare -- callers upstream (e.g.
// fingerprinter.py's clean_snmp_string()) already parse exactly this
// shape and are left untouched. Exit code mirrors net-snmp's own CLI:
// 0 with output on success, non-zero on any failure (timeout, auth
// failure, bad args) -- adaptive_snmp_query()'s existing `if
// proc.returncode != 0: return None` check works identically
// regardless of which OS is underneath.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

type credentialInput struct {
	Version      string `json:"version"` // "v2c" or "v3"
	Community    string `json:"community,omitempty"`
	Username     string `json:"username,omitempty"`
	AuthProtocol string `json:"auth_protocol,omitempty"` // strength-named: MD5/SHA/SHA-224/SHA-256/SHA-384/SHA-512
	AuthPassword string `json:"auth_password,omitempty"`
	PrivProtocol string `json:"priv_protocol,omitempty"` // strength-named: DES/AES-128/AES-192/AES-256
	PrivPassword string `json:"priv_password,omitempty"`
}

func mapAuthProtocol(name string) (gosnmp.SnmpV3AuthProtocol, bool) {
	switch name {
	case "MD5":
		return gosnmp.MD5, true
	case "SHA":
		return gosnmp.SHA, true
	case "SHA-224":
		return gosnmp.SHA224, true
	case "SHA-256":
		return gosnmp.SHA256, true
	case "SHA-384":
		return gosnmp.SHA384, true
	case "SHA-512":
		return gosnmp.SHA512, true
	}
	return gosnmp.NoAuth, false
}

func mapPrivProtocol(name string) (gosnmp.SnmpV3PrivProtocol, bool) {
	switch name {
	case "DES":
		return gosnmp.DES, true
	case "AES-128":
		return gosnmp.AES, true
	case "AES-192":
		return gosnmp.AES192, true
	case "AES-256":
		return gosnmp.AES256, true
	}
	return gosnmp.NoPriv, false
}

func buildParams(cred credentialInput, target string, timeout time.Duration, retries int) (*gosnmp.GoSNMP, error) {
	base := &gosnmp.GoSNMP{
		Target:  target,
		Port:    161,
		Timeout: timeout,
		Retries: retries,
	}

	switch cred.Version {
	case "v2c":
		base.Version = gosnmp.Version2c
		base.Community = cred.Community
		return base, nil

	case "v3":
		authProto, ok := mapAuthProtocol(cred.AuthProtocol)
		if !ok {
			return nil, fmt.Errorf("unsupported auth protocol: %q", cred.AuthProtocol)
		}
		privProto, ok := mapPrivProtocol(cred.PrivProtocol)
		if !ok {
			return nil, fmt.Errorf("unsupported priv protocol: %q", cred.PrivProtocol)
		}
		base.Version = gosnmp.Version3
		base.SecurityModel = gosnmp.UserSecurityModel
		base.MsgFlags = gosnmp.AuthPriv // run_snmp_command always requests authPriv (-l authPriv)
		base.SecurityParameters = &gosnmp.UsmSecurityParameters{
			UserName:                 cred.Username,
			AuthenticationProtocol:   authProto,
			AuthenticationPassphrase: cred.AuthPassword,
			PrivacyProtocol:          privProto,
			PrivacyPassphrase:        cred.PrivPassword,
		}
		return base, nil
	}

	return nil, fmt.Errorf("unsupported version: %q", cred.Version)
}

// isPrintableOctetString mirrors net-snmp's own heuristic for
// deciding how to render an OCTET STRING: text stays text, binary
// data (a raw MAC address being the dominant case here -- see
// ipNetToMediaPhysAddress) gets hex instead. Getting this wrong is
// not cosmetic: confirmed live against a real router's ARP table that
// treating every OCTET STRING as printable text silently corrupted
// every binary value into an unparseable escaped-byte string (Go's
// %q on 6 raw MAC-address bytes), which made ipNetToMediaPhysAddress
// parsing in engine/snmp_pipeline.py fail silently on every single
// entry (wrapped in a bare try/except) -- l3_bindings stayed
// completely empty despite the walk itself succeeding.
func isPrintableOctetString(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// formatValue reproduces net-snmp's `-On -Oq` textual convention
// closely enough for every caller in this codebase: printable OCTET
// STRING double-quoted (the two dominant caller patterns --
// clean_snmp_string() and a bare OID-prefix strip -- both key off
// that), a binary OCTET STRING (a raw MAC address being the dominant
// case) as space-separated uppercase hex bytes -- net-snmp's own
// convention for non-printable OctetString values, and what
// snmp_pipeline.py's ARP-table parser (raw_mac.replace(' ', ':'))
// actually expects. OBJECT IDENTIFIER dot-prefixed, everything else
// the plain decimal value. Confirmed against a real local snmpd's
// actual output before writing this, not assumed from the man page
// alone -- the binary-OctetString case specifically was confirmed
// against a real router's ARP table after the printable-only version
// was found silently corrupting every entry.
func formatValue(pdu gosnmp.SnmpPDU) string {
	switch pdu.Type {
	case gosnmp.OctetString:
		b, _ := pdu.Value.([]byte)
		if isPrintableOctetString(b) {
			return fmt.Sprintf("%q", string(b))
		}
		hexParts := make([]string, len(b))
		for i, c := range b {
			hexParts[i] = fmt.Sprintf("%02X", c)
		}
		return strings.Join(hexParts, " ")
	case gosnmp.ObjectIdentifier:
		s, _ := pdu.Value.(string)
		if !strings.HasPrefix(s, ".") {
			s = "." + s
		}
		return s
	case gosnmp.IPAddress:
		s, _ := pdu.Value.(string)
		return s
	default:
		return fmt.Sprintf("%v", gosnmp.ToBigInt(pdu.Value))
	}
}

func main() {
	if len(os.Args) < 6 {
		fmt.Fprintln(os.Stderr, "usage: netlanvas_snmp_helper <ip> <oid> <get|walk> <timeoutSeconds> <retries>  (credential JSON on stdin)")
		os.Exit(2)
	}
	ip := os.Args[1]
	oid := os.Args[2]
	mode := os.Args[3]
	timeoutSec, err := strconv.ParseFloat(os.Args[4], 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid timeout %q: %v\n", os.Args[4], err)
		os.Exit(2)
	}
	retries, err := strconv.Atoi(os.Args[5])
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid retries %q: %v\n", os.Args[5], err)
		os.Exit(2)
	}

	stdinBytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read credential from stdin: %v\n", err)
		os.Exit(2)
	}
	var cred credentialInput
	if err := json.Unmarshal(stdinBytes, &cred); err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse credential JSON: %v\n", err)
		os.Exit(2)
	}

	params, err := buildParams(cred, ip, time.Duration(timeoutSec*float64(time.Second)), retries)
	if err != nil {
		fmt.Fprintf(os.Stderr, "credential error: %v\n", err)
		os.Exit(1)
	}

	if err := params.Connect(); err != nil {
		fmt.Fprintf(os.Stderr, "connect error: %v\n", err)
		os.Exit(1)
	}
	defer params.Conn.Close()

	var pdus []gosnmp.SnmpPDU
	if mode == "walk" {
		pdus, err = params.WalkAll(oid)
	} else {
		var packet *gosnmp.SnmpPacket
		packet, err = params.Get([]string{oid})
		if err == nil && packet != nil {
			pdus = packet.Variables
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "snmp error: %v\n", err)
		os.Exit(1)
	}

	printed := 0
	for _, pdu := range pdus {
		if pdu.Type == gosnmp.NoSuchObject || pdu.Type == gosnmp.NoSuchInstance || pdu.Type == gosnmp.EndOfMibView {
			continue
		}
		fmt.Printf("%s %s\n", pdu.Name, formatValue(pdu))
		printed++
	}

	if printed == 0 {
		os.Exit(1)
	}
}
