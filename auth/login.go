/*
* Copyright 2022-2026 Thorsten A. Knieling
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
func InitLoginService(auth *Authentication) error {
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
			err := InitPasswordFile(s.PasswordFile)
			if err != nil {
				return err
			}
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
		case SQLDatabaseMethod:
			services.ServerMessage("Authentication using SQL database")
			RegisterTargetForAuth(s.Layer, s.Target, s.Module)
		case OIDCClientMethod:
			services.ServerMessage("Authentication using OIDC client")
			InitOIDC(s)
		case PluginMethod:
			services.ServerMessage("Authentication using plugin database")
			err := CallbackInit(s)
			if err != nil {
				return err
			}
		case CallbackMethod:
			services.ServerMessage("Authentication using callback database")
			err := CallbackInit(s)
			if err != nil {
				return err
			}
		default:
			panic("Error faulty authentication method: " + s.Type)
		}
	}
	return nil
}

// RemoveLoginService remove login service realm and authorization instances of user
func RemoveLoginService(auth *Authentication) {
	log.Log.Debugf("Remove login service")

	// Check configuration values and set defaults
	if len(auth.AuthenticationServer) == 0 {
		return
	}
	// Go through all login authentication services and activate them
	for _, s := range auth.AuthenticationServer {
		log.Log.Debugf("Remove authentication type <%s>", s.Type)
		s.AuthMethod = MethodType(s.Type)
		switch s.AuthMethod {
		case FileMethod:
			RemovePasswordFile(s.PasswordFile)
			services.ServerMessage("Remove Authentication password file type")
		case OIDCClientMethod:
		default:
			log.Log.Debugf("Remove of authentication type %s not possible", s.Type)
		}
	}
}
