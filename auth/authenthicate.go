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
	"strings"

	"github.com/tknie/log"
	"github.com/tknie/services"
)

// DefaultRoles default roles set for users
var DefaultRoles = []string{}

// Authenticate authenticate using user and password adding roles to the principal
// The principal interface need to be implemented to add roles corresponding to the
// defined system. If system does not provide roles the DefaultRoles will be added
// to principal instance
func (service *AuthenticationServer) Authenticate(principal PrincipalInterface, user, passwd string) error {
	log.Log.Debugf("Authenticate: %p -> %d", service, service.AuthMethod)
	switch service.AuthMethod {
	case FileMethod:
		log.Log.Debugf("Password file service user %s", user)
		roles, err := callPasswordFileUserAuthenticate(user, passwd)
		if err == nil {
			principal.AddRoles(strings.Split(roles, ","))
		}
		return err
	case SystemMethod:
		log.Log.Debugf("System service name %s", service.Module)
		principal.AddRoles(DefaultRoles)
		return callSystemAuthenticate(service.Module, user, passwd)
	case LDAPMethod:
		principal.AddRoles(DefaultRoles)
		return service.authLDAPRealm(user, passwd)
	case OpenIDMethod:
		principal.AddRoles(DefaultRoles)
		return service.authOpenID(user, passwd)
	case SQLDatabaseMethod:
		principal.AddRoles(DefaultRoles)
		log.Log.Debugf("SQL database service name %s", service.Module)
		return callDatabaseAuthenticate(service.Module, user, passwd)
	case PluginMethod:
		log.Log.Debugf("Plugin database service name %s", service.Module)
		return callbackPluginAuthenticate(service, principal, user, passwd)
	case CallbackMethod:
		log.Log.Debugf("Plugin database service name %s", service.Module)
		return callbackPluginAuthenticate(service, principal, user, passwd)
	default:
		log.Log.Debugf("Unknown service name %s", service.AuthMethod)
	}
	return errors.New("Authentication method error")
}

// Method used authorization method string info
func (authMethod Method) String() string {
	switch authMethod {
	case SystemMethod:
		return "System"
	case FileMethod:
		return "Realm properties"
	case LDAPMethod:
		return "LDAP"
	case OpenIDMethod:
		return "OpenID"
	case SQLDatabaseMethod:
		return "SQL"
	case PluginMethod:
		return "Plugin"
	case CallbackMethod:
		return "Callback"
	}
	return "Unknown"
}

func (service *AuthenticationServer) authLDAPRealm(u, password string) error {
	ldapList := service.LDAP
	for _, l := range ldapList {
		s, err := l.SearchEntry(u, password, false)
		if err != nil {
			services.ServerMessage("LDAP search error %s: %v", u, err)
			continue
		}
		if s.IsRestricted {
			services.ServerMessage("LDAP search restricted: %v", s.IsRestricted)
		}
		services.ServerMessage("LDAP search found user %s(%s)", s.Name, s.Mail)
		return nil
	}
	return services.NewError("SYS00002", u)
}

// authOpenID provides the possibility to authorize using OpenID Connect
func (service *AuthenticationServer) authOpenID(u, password string) error {
	return services.NewError("SYS00003")
}
