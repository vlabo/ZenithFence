//go:build windows
// +build windows

package main

import (
	"bufio"
	"fmt"
	"log"
	"os"

	"github.com/vlabo/portmaster_windows_rust_kext/kext_interface"
	"github.com/vlabo/portmaster_windows_rust_kext/kext_interface/Protocol"
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

	dataChan := make(chan *Protocol.Info)
	endChan := make(chan struct{})
	go func() {
		kext_interface.ReadInfo(file, dataChan)
	}()

	go func() {
		for true {
			select {
			case info := <-dataChan:
				{
					switch info.ValueType() {
					case Protocol.InfoUnionPacket:
						{
							packet := kext_interface.ReadPacket(info)
							log.Printf("connection from: %s", packet.ProcessPath())
							file.Write(kext_interface.GetVerdirctResponse(packet.Id(), int8(VerdictAccept)))
						}
					case Protocol.InfoUnionLogLine:
						{
							logLine := kext_interface.ReadLogLine(info)
							fmt.Println(string(logLine.Line()))
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
	endChan <- struct{}{}
	file.Write(kext_interface.GetShutdownRequest())
	// file.Write(kext_interface.GetVerdirctResponse(1, 2))
}
