//go:build windows
// +build windows

package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/vlabo/zenithfence/kext_interface"
)

type Verdict int8

var protocols = map[int]string{
	1:  "icmp",
	2:  "igmp",
	6:  "tcp",
	17: "udp",
	58: "ipv6-icmp",
}

const (
	// VerdictUndecided is the default status of new connections.
	VerdictUndecided           Verdict = 0
	VerdictUndeterminable      Verdict = 1
	VerdictAccept              Verdict = 2
	VerdictBlock               Verdict = 3
	VerdictDrop                Verdict = 4
	VerdictRerouteToNameserver Verdict = 5
	VerdictRerouteToTunnel     Verdict = 6
	VerdictFailed              Verdict = 7
)

func main() {
	driverName := "ZenithFence"
	sysPath := "C:\\Dev\\driver.sys"
	kext, err := kext_interface.CreateKextService(driverName, sysPath)
	if err != nil {
		log.Panicf("failed to create driver service: %s", err)
	}
	defer kext.Delete()

	err = kext.Start(true)
	if err != nil {
		log.Panicf("failed to start service: %s", err)
	}
	defer kext.Stop(true)

	file, err := kext.OpenFile(1024)
	if err != nil {
		log.Panicf("failed to open driver file: %s", err)
	}
	defer file.Close()

	version, err := kext_interface.ReadVersion(file)
	if err == nil {
		log.Printf("Kext  version: %d.%d.%d.%d\n", version[0], version[1], version[2], version[3])
		log.Printf("KextI version: %d.%d.%d.%d\n", kext_interface.InterfaceVersion[0], kext_interface.InterfaceVersion[1], kext_interface.InterfaceVersion[2], kext_interface.InterfaceVersion[3])
	} else {
		log.Printf("Error reading version: %s\n", err)
	}

	ticker := time.NewTicker(1 * time.Second)
	go func() {
		for {
			select {
			case <-ticker.C:
				err := kext_interface.SendGetLogsCommand(file)
				if err != nil {
					return
				}
			}
		}
	}()

	go func() {
		for true {
			info, err := kext_interface.RecvInfo(file)
			if err != nil {
				log.Printf("error reading from file %s", err)
				return
			}
			switch {
			case info.ConnectionV4 != nil:
				{
					conn := info.ConnectionV4
					// direction := "->"
					if conn.Direction == 1 {
						// direction = "<-"
						// kext_interface.WriteVerdictCommand(file, kext_interface.BuildVerdict(kext_interface.Verdict{Id: connection.Id, Verdict: uint8(VerdictBlock)}))
						kext_interface.SendVerdictCommand(file, kext_interface.Verdict{Id: conn.Id, Verdict: uint8(VerdictAccept)})
					} else {
						kext_interface.SendVerdictCommand(file, kext_interface.Verdict{Id: conn.Id, Verdict: uint8(VerdictAccept)})
					}
					// log.Printf("infov4: %d pid=%d %+v:%d %s %+v:%d %s\n", conn.Id, conn.ProcessId, net.IP(conn.LocalIp[:]), conn.LocalPort, direction, net.IP(conn.RemoteIp[:]), conn.RemotePort, protocols[int(conn.Protocol)])

				}
			case info.ConnectionV6 != nil:
				{
					conn := info.ConnectionV6
					// direction := "->"
					if conn.Direction == 1 {
						kext_interface.SendVerdictCommand(file, kext_interface.Verdict{Id: conn.Id, Verdict: uint8(VerdictAccept)})
						// direction = "<-"
					} else {
						kext_interface.SendVerdictCommand(file, kext_interface.Verdict{Id: conn.Id, Verdict: uint8(VerdictAccept)})
					}
					// log.Printf("infov6: %d pid=%d [%+v]:%d %s [%+v]:%d %s\n", conn.Id, conn.ProcessId, net.IP(conn.LocalIp[:]), conn.LocalPort, direction, net.IP(conn.RemoteIp[:]), conn.RemotePort, protocols[int(conn.Protocol)])

				}
			case info.ConnectionEndV4 != nil:
				{
					// conn := info.ConnectionEndV4
					// direction := "->"
					// if conn.Direction == 1 {
					// direction = "<-"
					// }
					// log.Printf("conn end v4: pid=%d %+v:%d %s %+v:%d %s\n", conn.ProcessId, net.IP(conn.LocalIp[:]), conn.LocalPort, direction, net.IP(conn.RemoteIp[:]), conn.RemotePort, protocols[int(conn.Protocol)])
				}
			case info.ConnectionEndV6 != nil:
				{
					// conn := info.ConnectionEndV6
					// direction := "->"
					// if conn.Direction == 1 {
					// 	direction = "<-"
					// }
					// log.Printf("conn end v6: pid=%d [%+v]:%d %s [%+v]:%d %s\n", conn.ProcessId, net.IP(conn.LocalIp[:]), conn.LocalPort, direction, net.IP(conn.RemoteIp[:]), conn.RemotePort, protocols[int(conn.Protocol)])
				}
			case info.LogLine != nil:
				{
					log.Println(info.LogLine.Line)
				}
			}
		}
	}()

	fmt.Print("Press enter to exit\n")
	input := bufio.NewScanner(os.Stdin)
	input.Scan()
	kext_interface.SendShutdownCommand(file)
}
