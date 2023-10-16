//go:build windows
// +build windows

package main

import (
	"bufio"
	"fmt"
	"log"
	"strings"

	// "net"
	"os"

	"github.com/vlabo/portmaster_windows_rust_kext/kext_interface"
)

type Verdict int8

const (
	// VerdictUndecided is the default status of new connections.
	VerdictUndecided      Verdict = 0
	VerdictUndeterminable Verdict = 1
	VerdictAccept         Verdict = 2
	VerdictBlock          Verdict = 3
	VerdictDrop           Verdict = 4
	VerdictRedirect       Verdict = 5
	VerdictFailed         Verdict = 7
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
							if strings.HasSuffix(*connection.ProcessPath, "brave.exe") {
								kext_interface.WriteCommand(file, kext_interface.BuildVerdict(connection.Id, uint8(VerdictDrop)))
							} else {
								kext_interface.WriteCommand(file, kext_interface.BuildVerdict(connection.Id, uint8(VerdictAccept)))
							}

							// path := *connection.ProcessPath

							// log.Printf("connection from: %d", *connection.ProcessId)
							// if packet.RemotePort() == 53 {
							// 	log.Println("Redirect dns")
							// 	file.Write(kext_interface.GetVerdirctResponse(packet.Id(), int8(VerdictAccept))) //.GetRedirectResponse(packet.Id(), net.IPv4(9, 9, 9, 9), 53))
							// } else {
							// 	log.Println("Allow connection")
							// 	file.Write(kext_interface.GetVerdirctResponse(packet.Id(), int8(VerdictAccept)))
							// }
							// file.Write(kext_interface.GetVerdirctResponse(packet.Id(), int8(VerdictAccept)))
						}
						// case Protocol.InfoUnionLogLine:
						// 	{
						// 		logLine := kext_interface.ReadLogLine(info)
						// 		fmt.Println(string(logLine.Line()))
						// 	}
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
