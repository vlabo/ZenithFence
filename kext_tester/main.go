//go:build windows

package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
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
	// Real-world simulation mode: the same agent, but driving a userspace fake
	// driver instead of a kernel service. Switched purely by the environment, so
	// the production binary is otherwise unchanged. runSimulation returns the
	// mock driver's exit code so a scenario's pass/fail propagates out.
	if pipeName := os.Getenv("ZF_SIM_PIPE"); pipeName != "" {
		os.Exit(runSimulation(pipeName))
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

// runSimulation drives the same read/verdict loop as production against a
// userspace fake driver. When ZF_SIM_DAEMON names the `zf-sim` binary the agent
// *loads and starts the mock driver itself* -- it spawns the daemon (which runs
// the real driver over mock_wdk via driver_entry), opens its pipe, and stops it
// on exit -- mirroring how production loads and starts the kernel driver before
// opening the device. With ZF_SIM_DAEMON unset it attaches to a daemon started
// separately. Returns the process exit code.
func runSimulation(pipeName string) int {
	daemonPath := os.Getenv("ZF_SIM_DAEMON")
	if daemonPath == "" {
		return runSimulationAttached(pipeName)
	}

	svc, err := kext_interface.CreateMockKextService(pipeName, daemonPath)
	if err != nil {
		log.Panicf("sim: %s", err)
	}
	defer svc.Delete()

	// Ctrl+C must tear the daemon down: the random producer runs forever, so
	// without this an interrupted agent would orphan the daemon (os.Exit on
	// signal skips deferred cleanup).
	installInterrupt(func() { _ = svc.Delete() })

	log.Printf("sim: loading and starting mock driver (%s)", daemonPath)
	if err := svc.Start(true); err != nil {
		log.Panicf("sim: failed to start mock driver: %s", err)
	}

	log.Printf("sim: opening fake driver \\\\.\\pipe\\%s", pipeName)
	file, err := svc.OpenFile(1024)
	if err != nil {
		log.Panicf("sim: failed to open driver pipe: %s", err)
	}
	defer file.Close()

	logInterfaceVersion()
	pumpEvents(file)

	// The pipe closed because the daemon exited on its own (a scenario finished).
	// Reap it and propagate its pass/fail exit code.
	code, _ := svc.Wait()
	log.Printf("sim: mock driver exited with code %d", code)
	return code
}

// runSimulationAttached connects to an already-running fake-driver daemon without
// starting one (ZF_SIM_DAEMON unset, e.g. the daemon launched separately under a
// debugger). The read/verdict loop is identical; only the driver's lifecycle is
// out of the agent's hands.
func runSimulationAttached(pipeName string) int {
	log.Printf("sim: attaching to fake driver \\\\.\\pipe\\%s", pipeName)
	file, err := kext_interface.OpenPipe(pipeName, 1024)
	if err != nil {
		log.Panicf("sim: failed to open pipe: %s", err)
	}
	defer file.Close()

	logInterfaceVersion()
	pumpEvents(file)
	return 0
}

// pumpEvents runs the read/verdict loop shared by every simulation mode: read one
// event, apply the verdict policy, repeat until the connection closes.
func pumpEvents(file *kext_interface.KextFile) {
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

// installInterrupt runs cleanup on the first Ctrl+C, then exits. Producer mode
// never ends on its own, so without this the daemon would be orphaned.
func installInterrupt(cleanup func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	go func() {
		<-ch
		log.Println("sim: interrupt received; stopping mock driver")
		cleanup()
		os.Exit(130)
	}()
}

// handleInfo applies the agent's verdict policy to one event. Shared by the
// production and simulation paths so the decision logic is identical.
func handleInfo(file *kext_interface.KextFile, info kext_interface.Info) {
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
