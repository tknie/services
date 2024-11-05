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

package service

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

var elog debug.Log

// LibEnvironment environment variable setting search for system libraries
const LibEnvironment = "PATH"

type myservice struct{}

func (m *Parameters) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue
	changes <- svc.Status{State: svc.StartPending}
	elog.Error(1, fmt.Sprintf("Arguments %#v", args))
	srv := m.ServiceFct.(Interface)
	err := srv.Run(m)
	if err != nil {
		return false, 1
	}
	done := make(chan bool)
	go checkCommandEnded(m, done)
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
loop:
	for {
		elog.Info(1, "Looping")
		select {
		case <-done:
			changes <- svc.Status{State: svc.StopPending}
			return
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
				// Testing deadlock from https://code.google.com/p/winsvc/issues/detail?id=4
				time.Sleep(100 * time.Millisecond)
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				srv.Shutdown(m)
				break loop
			case svc.Pause:
				changes <- svc.Status{State: svc.Paused, Accepts: cmdsAccepted}
			case svc.Continue:
				changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
			default:
				elog.Error(1, fmt.Sprintf("unexpected control request #%d", c))
			}
		}
	}
	changes <- svc.Status{State: svc.StopPending}
	return
}

func checkCommandEnded(env *Parameters, done chan<- bool) {
	err := env.Cmd.Wait()
	if err != nil {
		log.Log.Debugf("Wait command error: %v", err)
	}
	done <- true
}

// RunService run the service
func RunService(env *Parameters, isDebug bool) {
	inService, err := svc.IsWindowsService()
	if err != nil {
		fmt.Printf("failed to determine if we are running in service: %v\n", err)
		return
	}
	if !isDebug && !inService {
		fmt.Printf("not in windows service")
		return
	}

	if isDebug {
		elog = debug.New(env.Name)
	} else {
		elog, err = eventlog.Open(env.Name)
		if err != nil {
			return
		}
	}
	defer elog.Close()

	elog.Info(1, fmt.Sprintf("starting %s service", env.Name))
	run := svc.Run
	if isDebug {
		run = debug.Run
	}
	err = run(env.Name, env)
	if err != nil {
		elog.Error(1, fmt.Sprintf("%s service failed: %v", env.Name, err))
		return
	}
	elog.Info(1, fmt.Sprintf("%s service stopped", env.Name))
}

// IsService return if the process context is part of a service
func IsService() bool {
	inService, err := svc.IsWindowsService()
	if err != nil {
		log.Log.Debugf("failed to determine if we are running in service: %v", err)
		return false
	}
	return inService
}

func addDefaultPath(env *[]string, envPath, currentLibEnv string) {
	*env = append(*env, LibEnvironment+
		"="+envPath+string(os.PathSeparator)+string(os.PathSeparator)+"bin;"+os.Getenv(LibEnvironment))
}

// StatusService display status of the service
func StatusService(env *Parameters) error {
	m, err := mgr.Connect()
	if err != nil {
		log.Log.Debugf("Connect failed: %v", err)
		services.ServerMessage("Service connect failed: %v", err)
		return err
	}
	services.ServerMessage("Check service name %s", env.Name)
	defer m.Disconnect()
	s, err := m.OpenService(env.Name)
	if err != nil {
		log.Log.Debugf("Open service failed, service does not exists: %v", err)
		services.ServerMessage("Open service failed, service does not exists: %v", err)
		s.Close()
		return fmt.Errorf("service %s already exists", env.Name)
	}
	status, err := s.Query()
	if err != nil {
		log.Log.Debugf("Query service failed: %v", err)
		services.ServerMessage("Query service failed: %v", err)
		s.Close()
		return fmt.Errorf("service %s query failed", env.Name)
	}
	disState := ""
	switch status.State {
	case svc.Stopped:
		disState = "Stopped"
	case svc.StartPending:
		disState = "StartPending"
	case svc.StopPending:
		disState = "StopPending"
	case svc.Running:
		disState = "Running"
	case svc.ContinuePending:
		disState = "ContinuePending"
	case svc.PausePending:
		disState = "PausePending"
	case svc.Paused:
		disState = "Paused"
	}
	services.ServerMessage("Service available: %s", disState)
	s.Close()
	return nil
}
