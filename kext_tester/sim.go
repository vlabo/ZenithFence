package main

// The simulation mode and the verdict policy, shared by every OS. On Windows the
// same policy also drives the real kernel driver (see main_windows.go).

import (
	"fmt"
	"io"
	"log"
	"net"
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

// runSimulation drives the same read/verdict loop as production against the
// userspace mock driver: the real driver over a mock WDK, served on a named pipe
// (a Unix socket on Unix) by a Python script (`Sim.serve`, see sim/). The script
// owns the driver's lifecycle and the traffic; this only attaches, answers events
// with the verdict policy below, and returns once the script closes the endpoint.
// Returns the process exit code.
func runSimulation(pipeName string) int {
	log.Printf("sim: attaching to mock driver %s", kext_interface.SimEndpoint(pipeName))
	file, err := kext_interface.OpenSimConn(pipeName, 1024)
	if err != nil {
		log.Panicf("sim: failed to open driver endpoint: %s", err)
	}
	defer file.Close()

	logInterfaceVersion()
	pumpEvents(file)
	return 0
}

// pumpEvents runs the read/verdict loop: read one event, apply the verdict policy, repeat until the connection closes.
func pumpEvents(file io.ReadWriter) {
	for {
		info, err := kext_interface.RecvInfo(file)
		if err != nil {
			log.Printf("sim: connection closed: %s", err)
			return
		}
		handleInfo(file, info)
	}
}

func logInterfaceVersion() {
	log.Printf("sim: agent interface version %d.%d.%d.%d",
		kext_interface.InterfaceVersion[0], kext_interface.InterfaceVersion[1],
		kext_interface.InterfaceVersion[2], kext_interface.InterfaceVersion[3])
}

// handleInfo applies the agent's verdict policy to one event. Shared by the
// production and simulation paths so the decision logic is identical.
func handleInfo(file io.ReadWriter, info kext_interface.Info) {
	switch info := info.(type) {
	case *kext_interface.ConnectionV4:
		if info.Direction == 1 {
			kext_interface.SendVerdictCommand(file, kext_interface.Verdict{Id: info.Id, Verdict: uint8(kext_interface.VerdictPermanentAccept)})
			log.Printf("handling packet packet: %d pid=%d %+v:%d %s %+v:%d %s\n", info.Id, info.ProcessId, net.IP(info.LocalIp[:]), info.LocalPort, "->", net.IP(info.RemoteIp[:]), info.RemotePort, protocols[int(info.Protocol)])
		} else {
			if info.RemoteIp == [4]byte{1, 1, 1, 1} {
				kext_interface.SendVerdictCommand(file, kext_interface.Verdict{Id: info.Id, Verdict: uint8(kext_interface.VerdictPermanentBlock)})
				log.Printf("blocked packet: %d pid=%d %+v:%d %s %+v:%d %s\n", info.Id, info.ProcessId, net.IP(info.LocalIp[:]), info.LocalPort, "->", net.IP(info.RemoteIp[:]), info.RemotePort, protocols[int(info.Protocol)])
			} else {
				time.Sleep(20 * time.Millisecond)
				kext_interface.SendVerdictCommand(file, kext_interface.Verdict{Id: info.Id, Verdict: uint8(kext_interface.VerdictPermanentAccept)})
				log.Printf("handling packet packet: %d pid=%d %+v:%d %s %+v:%d %s\n", info.Id, info.ProcessId, net.IP(info.LocalIp[:]), info.LocalPort, "->", net.IP(info.RemoteIp[:]), info.RemotePort, protocols[int(info.Protocol)])
			}
		}
	case *kext_interface.ConnectionV6:
		kext_interface.SendVerdictCommand(file, kext_interface.Verdict{Id: info.Id, Verdict: uint8(kext_interface.VerdictPermanentAccept)})
		log.Printf("handling packet packet: %d pid=%d %+v:%d %s %+v:%d %s\n", info.Id, info.ProcessId, net.IP(info.LocalIp[:]), info.LocalPort, "->", net.IP(info.RemoteIp[:]), info.RemotePort, protocols[int(info.Protocol)])
	case *kext_interface.LogLine:
		log.Println(info.Line)
	case *kext_interface.ConnectionEndV4:
		log.Printf("ending connection: pid=%d %+v:%d %s %+v:%d %s\n", info.ProcessId, net.IP(info.LocalIp[:]), info.LocalPort, "->", net.IP(info.RemoteIp[:]), info.RemotePort, protocols[int(info.Protocol)])
	case *kext_interface.ConnectionEndV6:
		log.Printf("ending connection: pid=%d %+v:%d %s %+v:%d %s\n", info.ProcessId, net.IP(info.LocalIp[:]), info.LocalPort, "->", net.IP(info.RemoteIp[:]), info.RemotePort, protocols[int(info.Protocol)])
	default:
		panic(fmt.Sprintf("unexpected kext_interface.Info: %#v", info))
	}
}
