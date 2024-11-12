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
	"bytes"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/tknie/errorrepo"
	"github.com/tknie/log"
)

const (
	// TimeFormat time format schema
	TimeFormat = "2006/01/02 15:04:05.000"
)

// MessageReference default message reference
var MessageReference = "MSG"

// OutputMessageMode output messages if set
var OutputMessageMode = true
var msgLock sync.Mutex

// serverLogging server logging structure defining name and file descriptor information
type serverLogging struct {
	// ServerLogName server log name
	ServerLogName string
	// serverLogFile open file descriptor
	serverLogFile *os.File
}

var serverLog = new(serverLogging)

// Temporary buffer until server log is available
var tmpBuffer *bytes.Buffer

// EnableLogCache enable log cache
var EnableLogCache = true

// ServerErrorMessage Central output information
func ServerErrorMessage(msgID string, args ...interface{}) {
	switch t := args[0].(type) {
	case string:
		log.Log.Debugf("Error message: %s", t)
		msg := NewError(msgID, args...)

		ServerMessage(msg.Error())
	case *errorrepo.Error:
		ServerMessage(t.ID() + ": " + t.Error())
	}
}

// ServerMessage Central output information
func ServerMessage(msg string, args ...interface{}) {
	msgLock.Lock()
	defer msgLock.Unlock()
	d := time.Now().Format(TimeFormat)
	outMsg := fmt.Sprintf(d+" "+msg, args...)
	if OutputMessageMode {
		fmt.Printf(outMsg + LineBreak)
	}
	if i := strings.Index(outMsg, "password -> "); i > 0 {
		i += 12
		outMsg = outMsg[:i] + "**********"
	}
	log.Log.Debugf(outMsg)
	if EnableLogCache {
		if serverLog.serverLogFile == nil {
			if tmpBuffer == nil {
				tmpBuffer = &bytes.Buffer{}
			}
			tmpBuffer.WriteString(outMsg + LineBreak)
			return
		}
		if tmpBuffer != nil && tmpBuffer.Len() > 0 {
			serverLog.serverLogFile.Write(tmpBuffer.Bytes())
			tmpBuffer.Reset()
		}
	}
	serverLog.serverLogFile.WriteString(outMsg + LineBreak)
}

// OpenMessageLog Open message log
func (xlog *Logging) OpenMessageLog() {
	var sLogFileErr error
	serverLog.ServerLogName = os.ExpandEnv(xlog.ServerLocation)
	err := serverLog.checkLogFile()
	if err != nil {
		ServerMessage("Error managing message log file: %v"+LineBreak, err)
		os.Exit(1)
	}
	serverLog.serverLogFile, sLogFileErr = os.OpenFile(serverLog.ServerLogName, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if sLogFileErr != nil {
		wd, _ := os.Getwd()
		log.Log.Debugf("Error opening log file cwd=%v", wd)
		ServerMessage("Error opening message log file in %v -> %s: %v"+LineBreak, wd, xlog.ServerLocation, sLogFileErr)
		os.Exit(1)
	}
	ServerMessage("Output messages send to " + xlog.ServerLocation)
}

// CloseMessageLog Close message log
func CloseMessageLog() error {
	return serverLog.serverLogFile.Close()
}

func (sl *serverLogging) checkLogFile() error {
	if _, err := os.Stat(sl.ServerLogName); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	log.Log.Debugf("Message log exists: %s", sl.ServerLogName)
	for x := 1; x < 10000; x++ {
		slIndex := fmt.Sprintf("%s.%d", sl.ServerLogName, x)
		log.Log.Debugf("Check Message log: %s", slIndex)
		if _, err := os.Stat(slIndex); err != nil {
			if os.IsNotExist(err) {
				return os.Rename(sl.ServerLogName, slIndex)
			}
		}
	}
	return fmt.Errorf("index entry >10000")
}
