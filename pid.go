/*
* Copyright 2022-2026 Thorsten A. Knieling
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
	"bufio"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
)

// PidFileLocation pid file location for creating the PID file
var PidFileLocation = ""

func getPidFile() string {
	host, err := os.Hostname()
	if err != nil {
		host = ""
	} else {
		h := strings.IndexRune(host, '.')
		if h == -1 {
			h = len(host)
		}
		host = "." + host[:h]
	}
	p := PidFileLocation
	if p == "" {
		p = os.Getenv("TEMP")
	}
	if p == "" {
		p = "." + string(os.PathSeparator) + "tmp"
	}
	return p + string(os.PathSeparator) + "server" + host + ".pid"
}

// CreatePidFile create PID file
func CreatePidFile(flagPidFile string) error {
	pidFile := flagPidFile
	if pidFile == "" {
		pidFile = getPidFile()
	}
	if pidFile == "" {
		panic("PID File evaluation internal error")
	}
	fs, err := os.Stat(pidFile)
	if err == nil {
		if fs.IsDir() {
			return NewError("SYS00006", pidFile)
		}
		return NewError("SYS00007", pidFile)
	}
	if !os.IsNotExist(err) {
		return NewError("SYS00008", pidFile, err)
	}

	rf, err := os.OpenFile(pidFile, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		rf, err = os.OpenFile(pidFile, os.O_RDWR, 0666)
		if err != nil {
			ServerErrorMessage("SYS00029", pidFile)
			return err
		}
	}
	defer rf.Close()
	pid := os.Getpid()
	ServerMessage("Creating PID file for server pid=%d", pid)
	fmt.Fprintf(rf, "%d"+LineBreak, pid)

	c := make(chan os.Signal, 3)
	signal.Notify(c, handleSignal...)
	// signal.Notify(c, os.Kill, os.Interrupt)
	go func() {
		<-c // sig := <-c:
		DeletePidFile(flagPidFile)
	}()

	return nil
}

// DeletePidFile delete PID file
func DeletePidFile(flagPidFile string) error {
	pidFile := flagPidFile
	if pidFile == "" {
		pidFile = getPidFile()
	}
	err := os.Remove(pidFile)
	ServerMessage("Removing PID file %s...", pidFile)
	return err
}

// ReadPidFile read PID file
func ReadPidFile(flagPidFile string) (int, error) {
	pidFile := flagPidFile
	if pidFile == "" {
		pidFile = getPidFile()
	}
	rf, err := os.OpenFile(pidFile, os.O_RDONLY, 0)
	if err != nil {
		return -1, fmt.Errorf("error reading server PID file %s: %v", pidFile, err)
	}
	defer rf.Close()
	var pid int
	reader := bufio.NewReader(rf)
	var line string
	for {
		line, err = reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return 0, fmt.Errorf("error reading server PID file %s: %v", pidFile, err)
		}
		line = strings.Trim(line, " ")
		line = strings.Trim(line, LineBreak)
		if line != "" {
			pid, err = strconv.Atoi(line)
			if err != nil {
				return 0, fmt.Errorf("error reading server PID: %v", err)
			}
			break
		}
	}
	return pid, nil
}
