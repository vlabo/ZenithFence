//go:build windows

package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/vlabo/zenithfence/kext_interface"
)

func main() {
	// Real-world simulation mode: the same agent, but driving a userspace fake
	// driver instead of a kernel service. Switched purely by the environment, so
	// the production binary is otherwise unchanged. runSimulation attaches to the
	// endpoint a zfsim script serves (see sim/).
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
