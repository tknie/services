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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func xTestLDAPEntries(t *testing.T) {

	s := Source{Name: "Test",
		Host:              "activedirectory.Test",
		Port:              3268,
		SecurityProtocol:  SecurityProtocolStartTLS,
		SkipVerify:        true,
		BindDN:            "CN=Generic,OU=Generic,OU=Germany,DC=germany,DC=institute",
		BindPassword:      "Testme",
		AttributeUsername: "name",
		AttributeName:     "displayName",
		AttributeSurname:  "sn",
		AttributeMail:     "mail",
		AttributesInBind:  true,
		GroupsEnabled:     false,
		UserBase:          "ou=user,ou=Dallas,DC=us,DC=zone,DC=net",
		Filter:            "(&(objectClass=user)(name=%s)(memberOf=CN=Group,OU=Security Groups,OU=Germany,DC=germany,DC=institute))"}
	x, err := s.SearchEntries()
	if !assert.NoError(t, err) {
		return
	}
	assert.NotEmpty(t, x)
	for i, n := range x {
		fmt.Println("Entries ->", i, "username=", n.Username)
		fmt.Println("  Name        =", n.Name)
		fmt.Println("  Surname     =", n.Surname)
		fmt.Println("  Mail        =", n.Mail)
		fmt.Println("  IsAdmin     =", n.IsAdmin)
		fmt.Println("  IsRestricted=", n.IsRestricted)
	}
}
