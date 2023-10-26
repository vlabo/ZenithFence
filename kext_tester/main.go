//go:build windows
// +build windows

package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strings"

	// "net"
	"os"

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
	sysPath := "C:\\Dev\\portmaster-kext\\driver\\target\\x86_64-pc-windows-msvc\\debug\\driver.sys"
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

	file, err := kext.OpenFile()
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

	infoChan := make(chan *kext_interface.Info)
	endChan := make(chan struct{})
	go func() {
		kext_interface.ReadInfo(file, infoChan)
	}()

	go func() {
		for true {
			select {
			case info := <-infoChan:
				{
					switch {
					case info.Connection != nil:
						{
							connection := info.Connection
							log.Printf("info: %s\n", *connection.ProcessPath)
							if net.IP(connection.RemoteIp).Equal(net.IP([]uint8{1, 1, 1, 1})) {
								kext_interface.WriteCommand(file, kext_interface.BuildRedirect(kext_interface.Redirect{Id: connection.Id, RemoteAddress: []uint8{9, 9, 9, 9}, RemotePort: 53}))
							} else if strings.HasSuffix(*connection.ProcessPath, "brave.exe") {
								kext_interface.WriteCommand(file, kext_interface.BuildVerdict(kext_interface.Verdict{Id: connection.Id, Verdict: uint8(VerdictAccept)}))
							} else {
								kext_interface.WriteCommand(file, kext_interface.BuildVerdict(kext_interface.Verdict{Id: connection.Id, Verdict: uint8(VerdictAccept)}))
							}

						}
					}

				}
			case <-endChan:
				return
			}
		}
	}()

	fmt.Print("Press enter to exit\n")
	input := bufio.NewScanner(os.Stdin)
	input.Scan()
	// file.Close()
	kext_interface.WriteCommand(file, kext_interface.BuildShutdown())
	endChan <- struct{}{}
	// close(commandChan)
	// file.Write(kext_interface.GetShutdownRequest())
	// file.Write(kext_interface.GetVerdirctResponse(1, 2))
}
