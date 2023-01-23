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
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"strings"

	"github.com/tknie/log"
	"github.com/tknie/services"
)

var xmlFileHeader = `<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<!DOCTYPE properties SYSTEM "http://java.sun.com/dtd/properties.dtd">
`

type properties struct {
	Entry []entry `xml:"entry"`
}

type entry struct {
	Key     string `xml:"version,attr"`
	Content string `xml:",chardata"`
}

// Properties installation properties
type Properties struct {
	XMLName xml.Name `xml:"properties"`
	Entries []struct {
		Key  string `xml:"key,attr"`
		Name string `xml:",chardata"`
	} `xml:"entry"`
}

// Interface service interface for services
type Interface interface {
	Run(env *Parameters) error
	Shutdown(env *Parameters) error
}

// Parameters installation environment settings
type Parameters struct {
	Name         string
	DisplayName  string
	AppPath      string
	Description  string
	Path         string
	WrapperName  string
	Environments []string
	Parameters   []string
	ID           int
	User         string
	Password     string
	Group        string
	ServiceFct   Interface
	Cmd          *exec.Cmd
}

// InitService initialize installation environment structure
func InitService(name, appName, description string, svc Interface) *Parameters {
	ie := &Parameters{
		AppPath:     appName,
		Name:        strings.ToLower(name),
		Description: description,
		Path:        os.Getenv(services.DefaultEnvironment),
		ServiceFct:  svc,
	}
	userInfo, err := user.Current()
	if err == nil {
		ie.User = userInfo.Username
		if ie.Group == "" {
			g, err := user.LookupGroupId(userInfo.Gid)
			if err == nil {
				ie.Group = g.Name
			}
		}
	}
	if runtime.GOOS == "windows" && !strings.Contains(ie.User, "\\") {
		// Prefix local domain to user
		ie.User = ".\\" + ie.User
	}
	return ie

}

// ParseInstallXML parse install XML file
func (env *Parameters) ParseInstallXML(fileName string) error {
	file, err := os.OpenFile(fileName, os.O_RDONLY, 0666)
	// if we os.Open returns an error then handle it
	if err != nil {
		return err
	}
	byteValue, rerr := ioutil.ReadAll(file)
	if rerr != nil {
		services.ServerMessage("Error reading jobs persistents:", rerr)
		return rerr
	}
	var tj Properties
	err = xml.Unmarshal(byteValue, &tj)
	if err != nil {
		return err
	}
	fmt.Printf("Properties:" + services.LineBreak)
	for _, e := range tj.Entries {
		switch e.Key {
		case "suiteId":
			env.ID, err = strconv.Atoi(e.Name)
			if err != nil {
				return err
			}
			env.Name = "restserver"
		case "userName":
			env.User = e.Name
		case "groupName":
			env.Group = e.Name
		case "installDir":
			env.Path = e.Name
		}
		fmt.Printf(" %s: %s\n", e.Key, e.Name)
	}
	return nil
}

// AppDirectory provide path of installation
func (env *Parameters) AppDirectory() string {
	return env.Path + string(os.PathSeparator) + env.AppPath
}

// StartCommand execute application in given environment
func (env *Parameters) StartCommand(command string, arg []string) error {
	cmd := exec.Command(command, arg...)
	log.Log.Debugf("Start command: %s", cmd.Path)
	log.Log.Debugf("Start args   : %v", cmd.Args)

	log.Log.Debugf("Execute command %s with env:", command)
	for _, e := range os.Environ() {
		for _, p := range []string{"HOME", "LOGNAME", "HOST", "USER", "TEMP"} {
			if strings.HasPrefix(e, p) {
				log.Log.Debugf("Add  " + e)
				cmd.Env = append(cmd.Env, e)
				break
			}
		}
	}
	log.Log.Debugf("Old env end")

	cmd.Dir = env.Path + string(os.PathSeparator) + env.AppPath
	curdir := os.Getenv("CURDIR")
	if curdir == "" {
		curdir, _ = os.Getwd()
	}
	log.Log.Debugf("CURDIR=%s" + curdir)
	if curdir != "" {
		cmd.Env = append(cmd.Env, "CURDIR="+curdir)
	}
	debug := os.Getenv("ENABLE_DEBUG")
	if debug != "" {
		cmd.Env = append(cmd.Env, "ENABLE_DEBUG="+debug)
	}
	libEnv := os.Getenv(LibEnvironment)
	addDefaultPath(&(cmd.Env), env.Path, libEnv)

	if os.Getenv("NOWRAPPER") == "1" {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	} else {
		out, err := os.Create(env.AppDirectory() + "/logs/" + env.WrapperName + ".log")
		if err != nil {
			log.Log.Debugf("Error creating wrapper output: %v", err)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
		} else {
			cmd.Stdout = out
			outError, outErr := os.Create(env.AppDirectory() + "/logs/" + env.WrapperName + ".err")
			if outErr != nil {
				log.Log.Debugf("Error creating wrapper error file: %v", outErr)
				return outErr
			}
			cmd.Stderr = outError
		}
	}
	if log.IsDebugLevel() {
		log.Log.Debugf("Final env:")
		for _, e := range cmd.Env {
			log.Log.Debugf("Set: " + e)
		}
	}
	err := cmd.Start()
	if err != nil {
		log.Log.Debugf("Execute service error: %v", err)
		return err
	}
	env.Cmd = cmd
	/*err = cmd.Wait()
	if err != nil {
		log.Log.Debugf("Service executable %s exit with error: %v", cmd.Path, err)
		return err
	}*/
	log.Log.Debugf("Call started: %v", cmd.ProcessState.ExitCode())
	return nil
}

// AdaptConfigure load installation configuration and adapt service parameters to
// the installation parameters
func (env *Parameters) AdaptConfigure(name string) error {
	log.Log.Debugf("Input env %#v", env)
	log.Log.Debugf("Load config %s", name)
	installDir := os.Getenv("INSTALL_DIR")
	f, err := os.OpenFile(evaluateInstallConfig(installDir, name), os.O_RDONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	d, err := ioutil.ReadAll(f)
	if err != nil {
		return err
	}
	r := &properties{}
	err = xml.Unmarshal(d, r)
	if err != nil {
		return err
	}
	for _, e := range r.Entry {
		switch e.Key {
		case "suiteId":
			env.ID, err = strconv.Atoi(e.Content)
			if err != nil {
				return err
			}
		case "installDir":
			env.Path = e.Content
		case "Name":
			env.Name = e.Content
		case "appName":
			env.AppPath = e.Content
		case "userName":
			env.User = os.Getenv("ADA_REST_SERVICE_USER")
			if env.User == "" {
				env.User = e.Content
			}
			if runtime.GOOS == "windows" && !strings.Contains(env.User, "\\") {
				// Prefix local domain to user
				env.User = ".\\" + env.User
			}
		case "groupName":
			env.Group = os.Getenv("ADA_REST_SERVICE_GROUP")
			if env.Group == "" {
				env.Group = e.Content
			}
		}
	}
	log.Log.Debugf("Adapted env %#v", env)
	return nil
}

// evaluateInstallConfig if installDir is given, use the installDir=<path of installation> to
// evaluate the configuration file location
// If installDir is not given, use relative reference inside the installation location.
func evaluateInstallConfig(installDir, name string) string {
	separator := string(os.PathSeparator)
	dir := "INSTALL" +
		separator + "restenv.xml"
	if installDir != "" {
		dir = installDir + separator + name + separator + dir
	}
	return dir
}

// PrepareService generate installation configuration and write service parameters to
// the installation file
func (env *Parameters) PrepareService() error {
	f, err := os.OpenFile(evaluateInstallConfig(env.Path, env.AppPath), os.O_WRONLY|os.O_EXCL|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	r := &properties{}
	r.Entry = append(r.Entry, entry{Key: "suiteId", Content: strconv.Itoa(env.ID)})
	r.Entry = append(r.Entry, entry{Key: "installDir", Content: env.Path})
	r.Entry = append(r.Entry, entry{Key: "userName", Content: env.User})
	r.Entry = append(r.Entry, entry{Key: "groupName", Content: env.Group})
	r.Entry = append(r.Entry, entry{Key: "Name", Content: env.Name})
	r.Entry = append(r.Entry, entry{Key: "appName", Content: env.AppPath})
	f.Write([]byte(xmlFileHeader))
	d, err := xml.MarshalIndent(r, "", " ")
	if err != nil {
		return err
	}
	_, err = f.Write(d)
	if err != nil {
		return err
	}
	return nil
}
