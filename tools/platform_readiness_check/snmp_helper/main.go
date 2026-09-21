// netlanvas_snmp_helper -- proof-of-concept for WIN-9 in the punch list.
//
// Windows has no clean, trustworthy install path for snmpget/snmpwalk
// (confirmed via research: no winget package, no Chocolatey CLI package,
// Net-SNMP itself only ships Windows source, not a binary). Rather than
// point users at an unverified third-party binary, this is a small,
// purpose-built tool we build and own ourselves: a thin wrapper around
// gosnmp (github.com/gosnmp/gosnmp, BSD-licensed, pure Go, supports
// v1/v2c/v3 including v3's auth/privacy) that cross-compiles cleanly to
// a Windows .exe with no C toolchain needed at all.
//
// Only implements a single SNMP GET against one OID -- exactly what
// this proof-of-concept needs to prove the mechanism works (build once,
// push over the existing SSH-relay connection via SFTP, execute
// remotely, parse the result). Not a general-purpose SNMP tool; NOT
// wired into the real NetLanvas poller yet -- see readiness_check.py's
// Stage 9 for how this gets tested.
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/gosnmp/gosnmp"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: netlanvas_snmp_helper <host> <community> <oid>")
		os.Exit(2)
	}
	host := os.Args[1]
	community := os.Args[2]
	oid := os.Args[3]

	params := &gosnmp.GoSNMP{
		Target:    host,
		Port:      161,
		Community: community,
		Version:   gosnmp.Version2c,
		Timeout:   2 * time.Second,
		Retries:   0,
	}

	if err := params.Connect(); err != nil {
		fmt.Printf("CONNECT_ERROR: %v\n", err)
		os.Exit(1)
	}
	defer params.Conn.Close()

	result, err := params.Get([]string{oid})
	if err != nil {
		fmt.Printf("GET_ERROR: %v\n", err)
		os.Exit(1)
	}

	for _, v := range result.Variables {
		switch v.Type {
		case gosnmp.NoSuchObject, gosnmp.NoSuchInstance:
			fmt.Println("NO_SUCH_OBJECT")
			os.Exit(1)
		case gosnmp.OctetString:
			b, _ := v.Value.([]byte)
			fmt.Printf("OK: %s\n", string(b))
		default:
			fmt.Printf("OK: %v\n", v.Value)
		}
	}
}
