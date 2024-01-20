//go:build windows
// +build windows

package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/vlabo/portmaster_windows_rust_kext/kext_interface"
)

type Verdict int8

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
	driverName := "PortmasterTest"
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
		log.Printf("Kext version: %d.%d.%d.%d\n", version[0], version[1], version[2], version[3])
	} else {
		log.Printf("Error reading version: %s\n", err)
	}

	ticker := time.NewTicker(1 * time.Second)
	go func() {
		for {
			select {
			case <-ticker.C:
				kext_interface.WriteCommand(file, kext_interface.BuildGetLogs())
			}
		}
	}()

	go func() {
		for true {
			info, err := kext_interface.ReadInfo(file)
			if err != nil {
				log.Printf("error reading from file %s", err)
				return
			}
			switch {
			case info.Connection != nil:
				{
					connection := info.Connection
					log.Printf("info: %+v\n", connection)
					if net.IP(connection.RemoteIp).Equal(net.IP([]uint8{9, 9, 9, 9})) {
						kext_interface.WriteCommand(file, kext_interface.BuildRedirect(kext_interface.Redirect{Id: connection.Id, RemoteAddress: []uint8{1, 1, 1, 1}, RemotePort: 53}))
					} else
					// } else if strings.HasSuffix(*connection.ProcessPath, "brave.exe") {
					// 	kext_interface.WriteCommand(file, kext_interface.BuildVerdict(kext_interface.Verdict{Id: connection.Id, Verdict: uint8(VerdictAccept)}))
					// } else {
					if connection.Direction == 1 {
						kext_interface.WriteCommand(file, kext_interface.BuildVerdict(kext_interface.Verdict{Id: connection.Id, Verdict: uint8(VerdictBlock)}))
					} else {
						kext_interface.WriteCommand(file, kext_interface.BuildVerdict(kext_interface.Verdict{Id: connection.Id, Verdict: uint8(VerdictAccept)}))
					}
					// }

				}
			case info.LogLines != nil:
				{
					for _, logline := range *info.LogLines {
						log.Println(logline.Line)
					}
				}
			}
		}
	}()

	fmt.Print("Press enter to exit\n")
	input := bufio.NewScanner(os.Stdin)
	input.Scan()
	kext_interface.WriteCommand(file, kext_interface.BuildShutdown())
	file.Close()
}
