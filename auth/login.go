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
	"os"

	"github.com/tknie/log"
	"github.com/tknie/services"
)

var defaultPasswordFile = "configuration/auth.passwords"

// InitLoginService init login service realm and authorization instances of user
func InitLoginService(auth *Authentication) {
	log.Log.Debugf("Init login service")

	// Check configuration values and set defaults
	if len(auth.AuthenticationServer) == 0 {
		log.Log.Debugf("No authentication defined, set default Realm")
		service := &AuthenticationServer{}
		service.Type = "file"
		service.PasswordFile = defaultPasswordFile

		auth.AuthenticationServer = append(auth.AuthenticationServer, service)
	}
	// Go through all login authentication services and activate them
	for _, s := range auth.AuthenticationServer {
		log.Log.Debugf("Init authentication type <%s>", s.Type)
		s.AuthMethod = MethodType(s.Type)
		switch s.AuthMethod {
		case FileMethod:
			log.Log.Debugf("Authentication(%p): Auth using password file %s", s, os.ExpandEnv(s.PasswordFile))
			services.ServerMessage("Authentication realm in file %s", os.ExpandEnv(s.PasswordFile))
			InitPasswordFile(s.PasswordFile)
			// go Updater(auth)
		case SystemMethod:
			if s.Module == "" {
				s.Module = "login"
			}
			services.ServerMessage("Authentication using system login")
		case OpenIDMethod:
			services.ServerMessage("Authentication using OpenID Connect")
		case LDAPMethod:
			services.ServerMessage("Authentication using LDAP server")
		default:
			panic("Error faulty authentication method: " + s.Type)
		}
	}
}
