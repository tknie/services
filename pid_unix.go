//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris
// +build aix darwin dragonfly freebsd linux netbsd openbsd solaris

/*
* Copyright 2022-2023 Thorsten A. Knieling
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
 */

package services

import (
	"os"
	"syscall"
	"time"

	"github.com/mitchellh/go-ps"
)

// ShutdownServer shutdown server reference by PID file
func ShutdownServer(pidFile string, sleep int) {
	pid, err := ReadPidFile(pidFile)
	if err != nil {
		ServerMessage("Server pid reference not found: %v", err.Error())
		return
	}
	if pid != -1 {
		ServerMessage("Shutdown requested ...(unix like) pid=%d", pid)
		proc, err := os.FindProcess(pid)
		if err != nil {
			ServerMessage("Server process evaluation fail: %v", err)
			return
		}

		// Kill the process
		proc.Signal(syscall.SIGINT)
		maxTries := 10
		for maxTries > 0 {
			p, err := ps.FindProcess(pid)
			if err != nil {
				ServerMessage("Server find process error %T: %v", err, err)
				return
			}
			if p == nil {
				ServerMessage("Server process %d gone", pid)
				return
			}
			ServerMessage("Server pid %d shutdown request, waiting....", pid)
			time.Sleep(time.Duration(sleep) * time.Second)
			maxTries--
		}
		ServerMessage("Server shutdown request fails ...")
		return
	}
	ServerMessage("Server pid reference not found")
}
