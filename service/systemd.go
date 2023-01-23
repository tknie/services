//go:build linux
// +build linux

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
	"bytes"
	"fmt"
	"html/template"
	"os"
	"os/exec"
)

// Cmd command to be executed
type Cmd byte

const (
	// Start start the service
	Start Cmd = iota
	// Stop stop the service
	Stop
	// Pause pause the service (not on Unix)
	Pause
	// Continue continue the service (not on Unix)
	Continue
	// Status status of the service
	Status
)

// State state of the service
type State byte

const (
	// Running service is running
	Running State = iota
	// Stopped service is stopped
	Stopped
	// Paused service is paused
	Paused
)

// SystemPath system path for systemd configurations
var SystemPath = "/usr/lib/systemd/system"

// LibEnvironment environment variable setting search for system libraries
const LibEnvironment = "LD_LIBRARY_PATH"

const systemdConfTemplate = `[Unit]
Description={{.Description}}
ConditionPathExists={{.Path}}
After=network.target

[Service]
Type=simple
User={{.User}}
Group={{.Group}}

Restart=on-failure
Environment=INSTALL_DIR={{.Path}}
WorkingDirectory={{.Path}}/{{.AppPath}}
ExecStart={{.Path}}/{{.AppPath}}/bin/rest-service daemon
#ExecStop={{.Path}}/{{.AppPath}}/bin/rest-service stop

# make sure log directory exists and owned by syslog
PermissionsStartOnly=true
 
[Install]
WantedBy=multi-user.target
`

func addDefaultPath(env *[]string, envPath, currentLibEnv string) {
	*env = append(*env, LibEnvironment+
		"="+envPath+"/common/security/openssl/lib:"+
		envPath+":/lib:/usr/lib:"+currentLibEnv)
	*env = append(*env, "PATH=/usr/bin:/bin:/usr/sbin:/sbin")
}

// ServiceName used file name system name
func (env *Parameters) ServiceName() string {
	if env.ID > 0 {
		return fmt.Sprintf("%s%d", env.Name, env.ID)
	}
	return env.Name
}

// FileName used file name system file name plist
func (env *Parameters) FileName() string {
	if env.ID > 0 {
		return fmt.Sprintf("%s/%s%d.service", SystemPath, env.Name, env.ID)
	}
	return SystemPath + "/" + env.Name + ".service"
}

// InstallService install the service
func InstallService(env *Parameters) error {
	fileName := env.FileName()

	buf := bytes.NewBuffer(nil)

	tmplHead, err := parseTemplates()
	if err != nil {
		return err
	}

	// Generate header
	if err := tmplHead.Execute(buf, env); err != nil {
		return err
	}

	f, err := os.OpenFile(fileName, os.O_EXCL|os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(buf.String())
	if err != nil {
		return err
	}
	reloadService(env)
	return nil
}

// parseTemplates parse the template and adapt variables
func parseTemplates() (*template.Template, error) {
	tmplHead, err := template.New("header").Parse(systemdConfTemplate)
	if err != nil {
		return nil, err
	}
	return tmplHead, nil
}

// reloadService reload systemctl daemon
func reloadService(env *Parameters) {
	cmd := exec.Command("systemctl", "daemon-reload")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run()
}

// RemoveService remove the service
func RemoveService(env *Parameters) error {
	err := os.Remove(env.FileName())
	if err != nil {
		return err
	}
	reloadService(env)
	return err

}

// service start operation for the service
func service(op string, env *Parameters) error {
	cmd := exec.Command("systemctl", op, env.ServiceName())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	return err
}

// StartService start the service
func StartService(env *Parameters) error {
	return service("start", env)
}

// StopService stop the service
func StopService(env *Parameters) error {
	return service("stop", env)
}

// EnableService enable the service
func EnableService(env *Parameters) error {
	return service("enable", env)
}

// DisableService disable the service
func DisableService(env *Parameters) error {
	return service("disable", env)
}

// StatusService disable the status of the service
func StatusService(env *Parameters) error {
	return service("status", env)
}
