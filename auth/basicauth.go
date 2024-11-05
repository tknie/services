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

package auth

import (
	"net/http"
	"os"

	errors "github.com/go-openapi/errors"
	"github.com/tknie/log"
	"github.com/tknie/services"
)

// PrincipalInterface principal independent to model
type PrincipalInterface interface {
	UUID() string
	Name() string
	AddRoles([]string)
	Remote() string
	SetRemote(string)
	Roles() []string
	Session() interface{}
	SetSession(interface{})
}

var principalRegister []func(PrincipalInterface) error

// PrincipalCreater creator of an principal instance
var PrincipalCreater func(session *SessionInfo, user, pass string) PrincipalInterface

// AuthenticationConfig authentication config base
var AuthenticationConfig *Authentication

// Register register principal hooks
func Register(r func(PrincipalInterface) error) {
	principalRegister = append(principalRegister, r)
}

// BasicAuth basic authentication on REST
func BasicAuth(user string, pass string) (PrincipalInterface, error) {
	var saveErr error
	log.Log.Debugf("Basic authentication")
	if AuthenticationConfig == nil || len(AuthenticationConfig.AuthenticationServer) == 0 {
		services.ServerMessage("Fatal: No Authentication defined!!!!!")
		os.Exit(201)
	}
	sessionUUID := NewSessionInfo(user)
	principal := PrincipalCreater(sessionUUID, user, pass)
	for _, s := range AuthenticationConfig.AuthenticationServer {
		log.Log.Debugf("Check %s authentication (%p)", s.Type, s)
		err := s.Authenticate(principal, user, pass)
		if err == nil {
			log.Log.Debugf("Validated by %s authentication", s.Type)
			log.Log.Debugf("User authentication ok: %s", user)
			err = uuidStore(principal, user, pass)
			if err != nil {
				return nil, err
			}
			evaluateRoles(principal)
			if log.IsDebugLevel() {
				log.Log.Debugf("Create principal: %p", principal.Name)
			}
			return principal, nil
		}
		log.Log.Debugf("Authorization(%s/%p) refused for user %s: %v", s.AuthMethod, s, user, err)
		if saveErr == nil {
			saveErr = err
		}
	}
	services.ServerMessage("Authorization refused for user '%s': %v", user, saveErr)
	return nil, errors.New(http.StatusUnauthorized, "Access denied: %v", saveErr)
}
