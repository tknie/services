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

// Authenticate authenticate user and password
func (service *AuthenticationServer) Authenticate(principal PrincipalInterface, user, passwd string) error {
	log.Log.Debugf("Authenticate: %p -> %d", service, service.AuthMethod)
	switch service.AuthMethod {
	case FileMethod:
		log.Log.Debugf("Realm service user %s", user)
		roles, err := CheckPasswordFileUser(user, passwd)
		principal.AddRoles(strings.Split(roles, ","))
		return err
	case SystemMethod:
		log.Log.Debugf("System service name %s", service.Module)
		principal.AddRoles(DefaultRoles)
		return SystemAuthenticate(service.Module, user, passwd)
	case LDAPMethod:
		principal.AddRoles(DefaultRoles)
		return service.authLDAPRealm(user, passwd)
	case OpenIDMethod:
		principal.AddRoles(DefaultRoles)
		return service.authOpenID(user, passwd)
	case SQLDatabaseMethod:
		principal.AddRoles(DefaultRoles)
		return PerDatabase(service.Module, user, passwd)
	default:
		log.Log.Debugf("Unknown service name %s", service.AuthMethod.Method())
	}
	return errors.New("Authentication method error")
}

// Method used authorization method
func (authMethod Method) Method() string {
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
