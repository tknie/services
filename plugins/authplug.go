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

package main

import "github.com/tknie/services/auth"

type callback string

func (c *callback) GetName() string {
	return ""
}

// Init initialize plugin
func Init() error {
	return nil
}

// Authenticate authenticate using plugin
func Authenticate(principal auth.PrincipalInterface, userName, passwd string) error { return nil }

// CheckToken check token inside plugin
func CheckToken(token string, scopes []string) (auth.PrincipalInterface, error) { return nil, nil }

// GenerateToken generate token for the principal
func GenerateToken(IAt string, principal auth.PrincipalInterface) (tokenString string, err error) {
	return "", nil
}

// exported

// Callback callback for initialize plugin
var Callback callback
