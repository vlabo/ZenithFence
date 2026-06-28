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
	// Real-world simulation mode: the same agent, but connected to a userspace
	// fake driver over a named pipe instead of loading a kernel service. Switched
	// purely by the environment, so the production binary is otherwise unchanged.
	if pipeName := os.Getenv("ZF_SIM_PIPE"); pipeName != "" {
		runSimulation(pipeName)
		return
	}

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
		for {
			info, err := kext_interface.RecvInfo(file)
			if err != nil {
				log.Printf("error reading from file %s", err)
				return
			}
			handleInfo(file, info)
		}
	}()

	fmt.Print("Press enter to exit\n")
	input := bufio.NewScanner(os.Stdin)
	input.Scan()
	kext_interface.SendShutdownCommand(file)
}

// runSimulation drives the same read/verdict loop as production, but over a
// named-pipe connection to a userspace fake driver. It runs on the main
// goroutine and returns when the pipe closes (the daemon shut the driver down).
func runSimulation(pipeName string) {
	log.Printf("sim: connecting to fake driver \\\\.\\pipe\\%s", pipeName)
	file, err := kext_interface.OpenPipe(pipeName, 1024)
	if err != nil {
		log.Panicf("sim: failed to open pipe: %s", err)
	}
	defer file.Close()

	log.Printf("sim: agent interface version %d.%d.%d.%d",
		kext_interface.InterfaceVersion[0], kext_interface.InterfaceVersion[1],
		kext_interface.InterfaceVersion[2], kext_interface.InterfaceVersion[3])

	for {
		info, err := kext_interface.RecvInfo(file)
		if err != nil {
			log.Printf("sim: connection closed: %s", err)
			return
		}
		handleInfo(file, info)
	}
}

// handleInfo applies the agent's verdict policy to one event. Shared by the
// production and simulation paths so the decision logic is identical.
func handleInfo(file *kext_interface.KextFile, info kext_interface.Info) {
	switch info := info.(type) {
	case *kext_interface.ConnectionV4:
		if info.Direction == 1 {
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
	case *kext_interface.ConnectionV6:
		kext_interface.SendVerdictCommand(file, kext_interface.Verdict{Id: info.Id, Verdict: uint8(kext_interface.VerdictPermanentAccept)})
	case *kext_interface.LogLine:
		log.Println(info.Line)
	}
}
