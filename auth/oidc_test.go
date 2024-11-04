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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOIDCclient(t *testing.T) {

	clientID := os.Getenv("SERVICE_OIDC_CLIENT")
	if clientID == "" {
		return
	}

	auth := &AuthenticationServer{
		ClientID:     os.Getenv("SERVICE_OIDC_CLIENT"),
		ClientSecret: os.Getenv("SERVICE_OIDC_SECRET"),
		URL:          os.Getenv("SERVICE_OIDC_URL"),
		RedirectURL:  os.Getenv("SERVICE_OIDC_REDIRECTURL"),
	}
	err := InitOIDC(auth)
	if !assert.NoError(t, err) {
		return
	}
	username := os.Getenv("SERVICE_OIDC_USER")
	password := os.Getenv("SERVICE_OIDC_PASSWORD")

	principal := &testPrincipal{}
	err = callbackOIDCAuthenticate(auth, principal, username, password)
	assert.NoError(t, err)
}
