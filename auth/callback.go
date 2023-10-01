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

package auth

import (
	"errors"
	"fmt"
	"plugin"
)

// CallbackInterface callback interface for auth
type CallbackInterface interface {
	GetName() string
	Init() error
	Authenticate(principal PrincipalInterface, userName, passwd string) error
	CheckToken(token string, scopes []string) (PrincipalInterface, error)
	GenerateToken(IAt string, principal PrincipalInterface) (tokenString string, err error)
}

var callbackList = make([]CallbackInterface, 0)
var callbackMap = make(map[string]CallbackInterface)

// RegisterCallback register callback
func RegisterCallback(callback CallbackInterface) {
	callbackList = append(callbackList, callback)
	callbackMap[callback.GetName()] = callback
	service := &AuthenticationServer{Layer: callback.GetName(), AuthMethod: CallbackMethod}
	AuthenticationConfig.AuthenticationServer = append(AuthenticationConfig.AuthenticationServer, service)
}

// CallbackInit init login service realm and authorization instances of user using callbacks or plugins
func CallbackInit(auth *AuthenticationServer) error {
	if c, ok := callbackMap[auth.Layer]; ok {
		return c.Init()
	}
	return errors.New(auth.Layer + " callback not found")
}

// CallbackAuthenticate authenticate user and password to callback
func CallbackAuthenticate(auth *AuthenticationServer, principal PrincipalInterface, userName, passwd string) error {
	principal.AddRoles(DefaultRoles)
	if c, ok := callbackMap[auth.Layer]; ok {
		return c.Authenticate(principal, userName, passwd)
	}
	return errors.New(auth.Layer + " callback not found")
}

func checkCallbackToken(token string, scopes []string) (PrincipalInterface, error) {
	for _, c := range callbackMap {
		return c.CheckToken(token, scopes)
	}
	return nil, errors.New("no callback validates token")
}

func generateCallbackToken(IAt string, principal PrincipalInterface) (tokenString string, err error) {
	for _, c := range callbackMap {
		t, err := c.GenerateToken(IAt, principal)
		if err == nil {
			return t, err
		}
	}
	return "", errors.New("no callback generates token")
}

// RegisterPlugin register plugin
func RegisterPlugin() {

}

func loadPlugin(mod string) (*plugin.Plugin, error) {
	fmt.Println("Loading plugin ... " + mod)
	// load module
	// 1. open the so file to load the symbols
	plug, err := plugin.Open(mod)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return plug, nil
}
