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
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckUserWithXML(t *testing.T) {
	ClearUsers()
	err := LoadUsers(UserRole, "${CURDIR}/files/users-test.xml")
	assert.NoError(t, err)
	err = LoadUsers(AdministratorRole, "${CURDIR}/files/administrators-test.xml")
	assert.NoError(t, err)
	assert.False(t, ValidUser(UserRole, false, nil, "abc"))
	assert.False(t, ValidUser(UserRole, false, &UserInfo{}, "abc"))
	assert.False(t, ValidUser(UserRole, false, &UserInfo{User: "tkn"}, ""))
	assert.True(t, ValidUser(UserRole, false, &UserInfo{User: "user1"}, "db"))
	assert.False(t, ValidUser(UserRole, false, &UserInfo{User: "user1"}, "audit_data"))
	assert.True(t, ValidUser(UserRole, false, &UserInfo{User: "admin"}, "audit_data"))
	assert.False(t, ValidUser(UserRole, false, &UserInfo{User: "tkn"}, "audit_data"))
	assert.True(t, ValidUser(AdministratorRole, false, &UserInfo{User: "tkn"}, "audit_data"))
	assert.True(t, ValidUser(AdministratorRole, true, &UserInfo{User: "tkn"}, "audit_data"))
	assert.False(t, ValidUser(AdministratorRole, true, &UserInfo{User: "user1"}, "abc"))
	assert.True(t, ValidAdmin("admin"))
	assert.False(t, ValidAdmin("user1"))
	assert.False(t, ValidAdmin(""))
}

func TestCheckUserWithJSON(t *testing.T) {
	ClearUsers()
	users := Users{User: []*User{&User{Name: "abc"}}}
	v, _ := json.Marshal(users)
	fmt.Println(">>>", string(v))

	err := LoadUsers(UserRole, "${CURDIR}/files/users-test.json")
	assert.NoError(t, err)
	err = LoadUsers(AdministratorRole, "${CURDIR}/files/administrators-test.json")
	assert.NoError(t, err)
	assert.False(t, ValidUser(UserRole, false, nil, "abc"))
	assert.False(t, ValidUser(UserRole, false, &UserInfo{}, "abc"))
	assert.False(t, ValidUser(UserRole, false, &UserInfo{User: "tkn"}, ""))
	assert.True(t, ValidUser(UserRole, false, &UserInfo{User: "user1"}, "db"))
	assert.False(t, ValidUser(UserRole, false, &UserInfo{User: "user1"}, "audit_data"))
	assert.True(t, ValidUser(UserRole, false, &UserInfo{User: "admin"}, "audit_data"))
	assert.False(t, ValidUser(UserRole, false, &UserInfo{User: "tkn"}, "audit_data"))
	assert.True(t, ValidUser(AdministratorRole, false, &UserInfo{User: "tkn"}, "audit_data"))
	assert.True(t, ValidUser(AdministratorRole, true, &UserInfo{User: "tkn"}, "audit_data"))
	assert.False(t, ValidUser(AdministratorRole, true, &UserInfo{User: "user1"}, "abc"))
	assert.True(t, ValidAdmin("admin"))
	assert.False(t, ValidAdmin("user1"))
	assert.False(t, ValidAdmin(""))
}

func TestCheckUserWithYAML(t *testing.T) {
	ClearUsers()
	err := LoadUsers(UserRole, "${CURDIR}/files/users-test.yaml")
	assert.NoError(t, err)
	err = LoadUsers(AdministratorRole, "${CURDIR}/files/administrators-test.yaml")
	assert.NoError(t, err)
	assert.False(t, ValidUser(UserRole, false, nil, "abc"))
	assert.False(t, ValidUser(UserRole, false, &UserInfo{}, "abc"))
	assert.False(t, ValidUser(UserRole, false, &UserInfo{User: "tkn"}, ""))
	assert.True(t, ValidUser(UserRole, false, &UserInfo{User: "user1"}, "db"))
	assert.False(t, ValidUser(UserRole, false, &UserInfo{User: "user1"}, "audit_data"))
	assert.True(t, ValidUser(UserRole, false, &UserInfo{User: "admin"}, "audit_data"))
	assert.False(t, ValidUser(UserRole, false, &UserInfo{User: "tkn"}, "audit_data"))
	assert.True(t, ValidUser(AdministratorRole, false, &UserInfo{User: "tkn"}, "audit_data"))
	assert.True(t, ValidUser(AdministratorRole, true, &UserInfo{User: "tkn"}, "audit_data"))
	assert.False(t, ValidUser(AdministratorRole, true, &UserInfo{User: "user1"}, "abc"))
	assert.True(t, ValidAdmin("admin"))
	assert.False(t, ValidAdmin("user1"))
	assert.False(t, ValidAdmin(""))
}
