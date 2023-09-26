//go:build windows
// +build windows

package main

import (
	"bufio"
	"fmt"
	"log"
	"os"

	"github.com/vlabo/portmaster_windows_rust_kext/kext_interface"
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
	running := true

	go func() {
		for running {
			data := make([]byte, 1000)
			count, err := file.Read(data)
			if err != nil {
				log.Printf("faield to read %s", err)
				continue
			}
			if count == 0 {
				continue
			}
			packet := kext_interface.ParsePacket(data[0:count])
			log.Printf("connection from: %s\n", string(packet.ProcessPath()))
		}
	}()

	fmt.Print("Press enter to exit\n")
	input := bufio.NewScanner(os.Stdin)
	input.Scan()
	running = false
	data := kext_interface.GetShutdownRequest()
	file.Write(data)
}
