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
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

type testCallback struct {
	checkTokenErr    error
	generateTokenErr error
}

func (tc *testCallback) GetName() string { return "testCallback" }
func (tc *testCallback) Init() error     { return nil }
func (tc *testCallback) Authenticate(principal PrincipalInterface, userName, passwd string) error {
	return nil
}
func (tc *testCallback) CheckToken(token string, scopes []string) (PrincipalInterface, error) {
	if tc.checkTokenErr != nil {
		return nil, tc.checkTokenErr
	}
	return &testPrincipal{}, tc.checkTokenErr
}
func (tc *testCallback) GenerateToken(IAt string,
	principal PrincipalInterface) (tokenString string, err error) {
	if tc.generateTokenErr != nil {
		return "", tc.generateTokenErr
	}
	return "TESTTOKEN", tc.generateTokenErr
}

func TestJWTCallback(t *testing.T) {
	defer ClearCallbacks()
	AuthenticationConfig = &Authentication{}
	callback := &testCallback{}
	RegisterCallback(callback)
	wt := &WebToken{}

	tp := &testPrincipal{}
	token, err := wt.GenerateJWToken("*", tp)
	assert.NoError(t, err)
	assert.Equal(t, "TESTTOKEN", token)
	p, err := wt.JWTContainsRoles(token, []string{"abc"})
	assert.NoError(t, err)
	assert.IsType(t, p, tp)
}

func TestJWTCallbackFail(t *testing.T) {
	defer ClearCallbacks()
	AuthenticationConfig = &Authentication{}
	err := errors.New("Generate error")
	callback := &testCallback{generateTokenErr: err, checkTokenErr: err}
	RegisterCallback(callback)
	wt := &WebToken{}

	tp := &testPrincipal{}
	token, err := wt.GenerateJWToken("*", tp)
	assert.Error(t, err)
	assert.Equal(t, "", token)
	callback.generateTokenErr = nil
	token, err = wt.GenerateJWToken("*", tp)
	assert.NoError(t, err)
	assert.Equal(t, "TESTTOKEN", token)

	p, err := wt.JWTContainsRoles(token, []string{"abc"})
	assert.Error(t, err)
	assert.Nil(t, p)

	callback.checkTokenErr = nil
	p, err = wt.JWTContainsRoles(token, []string{"abc"})
	assert.NoError(t, err)
	assert.IsType(t, p, tp)
}

func TestPluginAuth(t *testing.T) {
	pbin := os.Getenv("PLUGINBIN")
	loadPlugin(pbin + "/plugins.so")
}
