//go:build darwin || linux
// +build darwin linux

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

package service

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

var interrupt chan os.Signal

func signalNotify(interrupt chan<- os.Signal) {
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)
}

func handleInterrupt(once *sync.Once, env *Parameters, interrupt chan os.Signal) {
	once.Do(func() {
		for range interrupt {
			fmt.Println("Received signal interrupt")
			err := ShutdownService(env)
			if err != nil {
				fmt.Println("Error stopping", err)
			}
		}
	})
}

func prepareRun(env *Parameters) {
	p := os.Getenv("TEMP")
	if p == "" {
		p = env.AppDirectory() + string(os.PathSeparator) + "tmp"
	}
	_, err := os.Stat(p)
	if err != nil {
		if os.IsNotExist(err) {
			os.Mkdir(p, 0755)
		}
	}
}

// RunService run the service
func RunService(env *Parameters, isDebug bool) {
	prepareRun(env)
	interrupt = make(chan os.Signal, 1)
	signalNotify(interrupt)
	once := new(sync.Once)
	go handleInterrupt(once, env, interrupt)
	env.ServiceFct.Run(env)
}

// ShutdownService shutdown service
func ShutdownService(env *Parameters) error {
	return env.ServiceFct.Shutdown(env)
}

// ControlService control the service
func ControlService(env *Parameters, c Cmd, to State) error {
	switch c {
	case Start:
		return StartService(env)
	case Stop:
		return StopService(env)
	case Continue:
		return EnableService(env)
	case Pause:
		return DisableService(env)
	case Status:
		return StatusService(env)
	default:
	}
	return nil
}

// IsService return if the process context is part of a service
func IsService() bool {
	return false
}
