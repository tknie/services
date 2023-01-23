//go:build darwin
// +build darwin

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

	"github.com/tknie/services"
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
	// Status of the service
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

// SystemPath system path of launchdaemon configuration location
var SystemPath = "/Library/LaunchDaemons"

// LibEnvironment environment variable setting search for system libraries
const LibEnvironment = "DYLD_LIBRARY_PATH"

const header = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + services.LineBreak
const systemdConfTemplate = `<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- @${DAEMON_ID}@ -->
<plist version="1.0">
<dict>
        <key>Label</key>
        <string>xx.in.restserver.{{.Name}}</string>
        <key>ProgramArguments</key>
        <array>
            <string>{{.Path}}/{{.AppPath}}/bin/service-command</string>
            <string>daemon</string>
        </array>
		<key>EnvironmentVariables</key>
		<dict>
			<key>INSTALL_DIR</key>
			<string>{{.Path}}</string>
		</dict>
		<key>WorkingDirectory</key>
		<string>{{.Path}}/{{.AppPath}}</string>
		<key>Disabled</key> <false/>
        <key>RunAtLoad</key> <true/>
        <key>KeepAlive</key>
		<dict>
			<key>SuccessfulExit</key>
			<true/>
		</dict>
		<key>AbandonProcessGroup</key> <true/>
        <key>UserName</key> <string>{{.User}}</string>
        <key>GroupName</key> <string>{{.Group}}</string>
		<key>StandardErrorPath</key>
        <string>{{.Path}}/{{.AppPath}}/logs/service.err</string>
        <key>StandardOutPath</key>
        <string>{{.Path}}/{{.AppPath}}/logs/service.out</string>
</dict>
</plist>
`

func addDefaultPath(env *[]string, envPath, currentLibEnv string) {
	*env = append(*env, LibEnvironment+
		"="+envPath+"/common/security/openssl/lib:"+
		envPath+":/lib:/usr/lib:"+currentLibEnv)
	*env = append(*env, "PATH=/usr/bin:/bin:/usr/sbin:/sbin")
}

// InstallService install the service
func InstallService(env *Parameters) error {
	buf := bytes.NewBuffer(nil)

	tmplHead, err := parseTemplates()
	if err != nil {
		return err
	}

	// Generate header
	if err := tmplHead.Execute(buf, env); err != nil {
		return err
	}

	f, err := os.OpenFile(env.FileName(), os.O_EXCL|os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(header)
	if err != nil {
		return err
	}
	_, err = f.WriteString(buf.String())
	return err
}

func parseTemplates() (*template.Template, error) {
	tmplHead, err := template.New("header").Parse(systemdConfTemplate)
	if err != nil {
		return nil, err
	}
	return tmplHead, nil
}

// FileName used file name system file name plist
func (env *Parameters) FileName() string {
	if env.ID > 0 {
		return fmt.Sprintf("%s/in.xxx.%s%d.plist", SystemPath, env.Name, env.ID)

	}
	return SystemPath + "/in.xxx." + env.Name + ".plist"
}

// RemoveService remove the service
func RemoveService(env *Parameters) error {
	err := StopService(env)
	if err != nil {
		return err
	}
	fn := env.FileName()
	_, err = os.Stat(fn)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
	}
	return os.Remove(fn)
}

// service start the service
func service(op string, env *Parameters) error {
	cmd := exec.Command("launchctl", op, env.FileName())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	return err
}

// StartService start the service
func StartService(env *Parameters) error {
	return service("load", env)
}

// StopService stop the service
func StopService(env *Parameters) error {
	return service("unload", env)
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
