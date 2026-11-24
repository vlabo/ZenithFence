package kext_interface

import (
	_ "embed"
	"strconv"
	"strings"
)

var (
	//go:embed version.txt
	versionTxt string

	// 4 byte version of the Kext interface
	InterfaceVersion = func() (v [4]byte) {
		// Parse version from file "version.txt". Expected format: [0, 1, 2, 3]
		s := strings.TrimSpace(versionTxt)
		s = strings.TrimPrefix(s, "[")
		s = strings.TrimSuffix(s, "]")
		str_ver := strings.Split(s, ",")
		for i := range v {
			n, err := strconv.Atoi(strings.TrimSpace(str_ver[i]))
			if err != nil {
				panic(err)
			}
			v[i] = byte(n)
		}
		return
	}()
)
