/*
* Copyright 2022-2025 Thorsten A. Knieling
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
 */

package main

import (
	"fmt"
	"log"
	"os"

	"github.com/tknie/services/service"
)

const svcName = "myservice"

// SVC SVC structure
type SVC struct {
}

// Run run the service
func (svc *SVC) Run(env *service.Parameters) error {
	/*execCommand := os.Getenv("ADA_REST_SERVER_CMD")
	if execCommand == "" {
		execCommand = env.AppDirectory() + string(os.PathSeparator) + env.AppPath
	}
	arg := []string{"server"}
	return env.Execute(execCommand, arg)*/
	return fmt.Errorf("error running service")
}

// Shutdown shutdown service
func (svc *SVC) Shutdown(env *service.Parameters) error {
	fmt.Println("Stop of service called")
	/*	execCommand := os.Getenv("ADA_REST_CLIENT_CMD")
		if execCommand == "" {
			execCommand = env.AppDirectory() + string(os.PathSeparator) + env.AppPath
		}
		arg := []string{"client", "-s"}
		 return env.Execute(execCommand, arg)*/
	return fmt.Errorf("error shutdown service")
}

func main() {
	env := service.InitService("testsvc", ".",
		"Service to start the RESTful server", &SVC{})
	env.Name = svcName

	if service.IsService() || os.Args[1] == "run" {
		service.RunService(env, false)
		return
	}

	var err error
	switch os.Args[1] {
	case "installStart":
		err = env.AdaptConfigure(".")
		if err != nil {
			fmt.Println("Error adapting installation configuration:", err)
			return
		}
		err = service.InstallService(env)
		if err != nil {
			fmt.Println("Error installing service:", err)
			return
		}
		err = service.StartService(env)
	case "install":
		err = service.InstallService(env)
	case "remove":
		err = service.RemoveService(env)
	case "start":
		err = service.StartService(env)
	default:
		log.Fatal("Unknown command " + os.Args[1])
	}
	if err != nil {
		log.Fatal("Error", err)
	}
}
