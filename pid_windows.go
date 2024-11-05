//go:build windows
// +build windows

/*
* Copyright 2022-2024 Thorsten A. Knieling
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
)

// ShutdownServer shutdown server reference by PID file
func ShutdownServer(pidFile string, sleep int) {
	pid, err := ReadPidFile(pidFile)
	if err != nil {
		ServerMessage("Server pid reference not found: %v", err.Error())
		return
	}
	if pid != -1 {
		ServerMessage("Shutdown requested ...(windows-like) pid=%d", pid)
		proc, err := os.FindProcess(pid)
		if err != nil {
			ServerMessage("Server process evaluation fail: %v", err)
			return
		}

		err = proc.Kill()
		if err != nil {
			ServerMessage("Server process kill fail: %v", err)
			return
		}

		ServerMessage("Wait shutdown finished ...")
		return
	}
	ServerMessage("Server pid reference not found")
}
