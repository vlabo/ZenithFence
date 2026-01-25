//go:build windows

package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
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
		for range ticker.C {
			err := kext_interface.SendGetLogsCommand(file)
			if err != nil {
				return
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
			switch info := info.(type) {
			case *kext_interface.ConnectionV4:
				{
					// direction := "->"
					if info.Direction == 1 {
						// direction = "<-"
						// kext_interface.WriteVerdictCommand(file, kext_interface.BuildVerdict(kext_interface.Verdict{Id: connection.Id, Verdict: uint8(VerdictBlock)}))
						kext_interface.SendVerdictCommand(file, kext_interface.Verdict{Id: info.Id, Verdict: uint8(kext_interface.VerdictPermanentAccept)})
					} else {
						if info.RemoteIp == [4]byte{1, 1, 1, 1} {
							kext_interface.SendVerdictCommand(file, kext_interface.Verdict{Id: info.Id, Verdict: uint8(kext_interface.VerdictPermanentBlock)})
							log.Printf("blocked packet: %d pid=%d %+v:%d %s %+v:%d %s\n", info.Id, info.ProcessId, net.IP(info.LocalIp[:]), info.LocalPort, "->", net.IP(info.RemoteIp[:]), info.RemotePort, protocols[int(info.Protocol)])
						} else {
							time.Sleep(200 * time.Millisecond)
							kext_interface.SendVerdictCommand(file, kext_interface.Verdict{Id: info.Id, Verdict: uint8(kext_interface.VerdictPermanentAccept)})
						}
					}

					// log.Printf("infov4: %d pid=%d %+v:%d %s %+v:%d %s\n", conn.Id, conn.ProcessId, net.IP(conn.LocalIp[:]), conn.LocalPort, direction, net.IP(conn.RemoteIp[:]), conn.RemotePort, protocols[int(conn.Protocol)])
				}
			case *kext_interface.ConnectionV6:
				{
					// direction := "->"
					if info.Direction == 1 {
						kext_interface.SendVerdictCommand(file, kext_interface.Verdict{Id: info.Id, Verdict: uint8(kext_interface.VerdictPermanentAccept)})
						// direction = "<-"
					} else {
						kext_interface.SendVerdictCommand(file, kext_interface.Verdict{Id: info.Id, Verdict: uint8(kext_interface.VerdictPermanentAccept)})
					}
					// log.Printf("infov6: %d pid=%d [%+v]:%d %s [%+v]:%d %s\n", conn.Id, conn.ProcessId, net.IP(conn.LocalIp[:]), conn.LocalPort, direction, net.IP(conn.RemoteIp[:]), conn.RemotePort, protocols[int(conn.Protocol)])
				}
			case *kext_interface.ConnectionEndV4:
				{
					// conn := info.ConnectionEndV4
					// direction := "->"
					// if conn.Direction == 1 {
					// direction = "<-"
					// }
					// log.Printf("conn end v4: pid=%d %+v:%d %s %+v:%d %s\n", conn.ProcessId, net.IP(conn.LocalIp[:]), conn.LocalPort, direction, net.IP(conn.RemoteIp[:]), conn.RemotePort, protocols[int(conn.Protocol)])
				}
			case *kext_interface.ConnectionEndV6:
				{
					// conn := info.ConnectionEndV6
					// direction := "->"
					// if conn.Direction == 1 {
					// 	direction = "<-"
					// }
					// log.Printf("conn end v6: pid=%d [%+v]:%d %s [%+v]:%d %s\n", conn.ProcessId, net.IP(conn.LocalIp[:]), conn.LocalPort, direction, net.IP(conn.RemoteIp[:]), conn.RemotePort, protocols[int(conn.Protocol)])
				}
			case *kext_interface.LogLine:
				{
					log.Println(info.Line)
				}
			}
		}
	}()

	fmt.Print("Press enter to exit\n")
	input := bufio.NewScanner(os.Stdin)
	input.Scan()
	kext_interface.SendShutdownCommand(file)
}
