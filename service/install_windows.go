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
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

func exePath() (string, error) {
	prog := os.Args[0]
	p, err := filepath.Abs(prog)
	if err != nil {
		return "", err
	}
	fi, err := os.Stat(p)
	if err == nil {
		if !fi.Mode().IsDir() {
			return p, nil
		}
		err = fmt.Errorf("%s is directory", p)
	}
	if filepath.Ext(p) == "" {
		p += ".exe"
		fi, err := os.Stat(p)
		if err == nil {
			if !fi.Mode().IsDir() {
				return p, nil
			}
			err = fmt.Errorf("%s is directory", p)
		}
	}
	return "", err
}

// InstallService install the service
func InstallService(env *Parameters) error {
	exepath, err := exePath()
	if err != nil {
		return err
	}
	log.Log.Debugf("Exec path -> %s", exepath)
	m, err := mgr.Connect()
	if err != nil {
		log.Log.Debugf("Connect failed: %v", err)
		services.ServerMessage("Service connect failed: %v", err)
		return err
	}
	services.ServerMessage("Service connected")
	defer m.Disconnect()
	s, err := m.OpenService(env.Name)
	if err == nil {
		log.Log.Debugf("Open service failed, service exists %s", env.Name)
		services.ServerMessage("Open service failed, service already exists: %s", env.Name)
		s.Close()
		return fmt.Errorf("service %s already exists", env.Name)
	}

	// Define service parameters
	config := mgr.Config{StartType: mgr.StartAutomatic, ServiceStartName: env.User,
		DisplayName: env.DisplayName, Description: env.Description}
	if env.User != "" {
		config.ServiceStartName = env.User
		config.Password = env.Password
	}

	// Create the Windows service
	s, err = m.CreateService(env.Name, exepath, config, env.Parameters...)
	if err != nil {
		log.Log.Debugf("Create service failed: %s, %v", env.Name, err)
		services.ServerMessage("Create service failed: %s, %v", env.Name, err)
		return err
	}
	defer s.Close()
	err = eventlog.InstallAsEventCreate(env.Name, eventlog.Error|eventlog.Warning|eventlog.Info)
	if err != nil {
		log.Log.Debugf("Install as event failed: %s, %v", env.Name, err)
		services.ServerMessage("Install as event failed: %s, %v", env.Name, err)
		s.Delete()
		return fmt.Errorf("SetupEventLogSource() failed: %s", err)
	}
	services.ServerMessage("Install service successfully: %s", env.Name)
	return nil
}

// RemoveService remove the service
func RemoveService(env *Parameters) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(env.Name)
	if err != nil {
		services.ServerMessage("Service %s is not installed", env.Name)
		return fmt.Errorf("service %s is not installed", env.Name)
	}
	defer s.Close()
	status, sterr := s.Query()
	if sterr != nil {
		services.ServerMessage("Service %s status query fails: %v", env.Name, sterr)
		return fmt.Errorf("Service %s status query fails: %v", env.Name, sterr)
	}
	if status.State != svc.Stopped {
		status, err := s.Control(svc.Stop)
		if err != nil {
			return fmt.Errorf("could not send stop: %v", err)
		}
		// Wait for some seconds to wait for stop of service
		time.Sleep(15 * time.Second)
		status, sterr = s.Query()
		if sterr != nil {
			services.ServerMessage("Service %s status query stop fails: %v", env.Name, sterr)
			return fmt.Errorf("Service %s status query stop fails: %v", env.Name, sterr)
		}
		if status.State != svc.Stopped {
			services.ServerMessage("Service %s not stopped: %v", env.Name, sterr)
			return fmt.Errorf("Service %s not stopped: %v", env.Name, sterr)
		}
	}
	err = s.Delete()
	if err != nil {
		return err
	}
	err = eventlog.Remove(env.Name)
	if err != nil {
		return fmt.Errorf("RemoveEventLogSource() failed: %s", err)
	}
	return nil
}
