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
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

var auth *AuthenticationServer
var clientID = os.Getenv("SERVICE_OIDC_CLIENT")

func init() {
	auth = &AuthenticationServer{
		ClientID:     clientID,
		ClientSecret: os.Getenv("SERVICE_OIDC_SECRET"),
		URL:          os.Getenv("SERVICE_OIDC_URL"),
		RedirectURL:  os.Getenv("SERVICE_OIDC_REDIRECTURL"),
	}
	err := InitOIDC(auth)
	if err != nil {
		fmt.Println("Error initializing auth:", err)
	}

}

func TestOIDCclient(t *testing.T) {

	if clientID == "" {
		return
	}

	username := os.Getenv("SERVICE_OIDC_USER")
	password := os.Getenv("SERVICE_OIDC_PASSWORD")

	principal := &testPrincipal{}
	err := callbackOIDCAuthenticate(auth, principal, username, password)
	assert.NoError(t, err)

	token, ok := principal.Session().(*oauth2.Token)
	assert.True(t, ok)

	webToken := &WebToken{OAuth2: true}
	err = webToken.InitWebTokenJose2()
	if !assert.NoError(t, err) {
		return
	}
	generatedToken, err := webToken.GenerateJWToken("", principal)
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, token.AccessToken, generatedToken)

	PrincipalCreater = func(session *SessionInfo, user, pass string) PrincipalInterface {
		fmt.Println("Principal created:", user, pass)
		return &testPrincipal{token: pass, user: user}
	}
	p, err := webToken.JWTContainsRoles(generatedToken, []string{"test"})
	if !assert.NoError(t, err) {
		return
	}

	principal, ok = p.(*testPrincipal)
	assert.True(t, ok)
	assert.Equal(t, principal.user, username)
	assert.Equal(t, principal.token, generatedToken)
}

func TestOIDCExpiredClient(t *testing.T) {
	PrincipalCreater = func(session *SessionInfo, user, pass string) PrincipalInterface {
		fmt.Println("Principal created:", user, pass)
		return &testPrincipal{token: pass, user: user}
	}

	token := os.Getenv("SERVICE_OIDC_EXPIRED_TOKEN")
	if token == "" {
		return
	}

	webToken := &WebToken{OAuth2: true}
	p, err := webToken.JWTContainsRoles(token, []string{"test"})
	if !assert.Error(t, err) {
		return
	}
	assert.Nil(t, p)
	assert.Contains(t, err.Error(), "expired")
}
