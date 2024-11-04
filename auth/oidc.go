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
	"context"
	"errors"
	"fmt"

	"github.com/coreos/go-oidc"
	"github.com/tknie/log"
	"golang.org/x/oauth2"
)

var oauth2Config *oauth2.Config
var provider *oidc.Provider

func InitOIDC(auth *AuthenticationServer) error {
	if auth == nil {
		return errors.New("no OIDC client config given")
	}
	if auth.ClientID == "" || auth.ClientSecret == "" || auth.URL == "" {
		return errors.New("no OIDC client config details given")
	}
	var err error
	provider, err = oidc.NewProvider(context.Background(), auth.URL)
	if err != nil {
		log.Log.Debugf("Provider error: %s", err)
		return err
	}

	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config = &oauth2.Config{
		ClientID:     auth.ClientID,
		ClientSecret: auth.ClientSecret,
		// RedirectURL:  OIDCClient.RedirectURL,

		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}
	return nil
}

// callbackOIDCAuthenticate authenticate user and password to OIDC client
func callbackOIDCAuthenticate(auth *AuthenticationServer, principal PrincipalInterface, userName, passwd string) error {
	if oauth2Config == nil {
		return errors.New("no OIDC configured")
	}
	token, err := oauth2Config.PasswordCredentialsToken(context.Background(), userName, passwd)
	if err != nil {
		return err
	}
	principal.SetRemote("XX")
	principal.SetSession(token)
	return nil
}

// InitWebTokenOIDC init web token for OIDC
func (webToken *WebToken) InitWebTokenOIDC() error {
	return nil
}

// GenerateJWToken generate JWT token using golang Jose.v2
func (webToken *WebToken) GenerateOIDCToken(IAt string, principal PrincipalInterface) (tokenString string, err error) {
	token, ok := principal.Session().(oauth2.Token)
	if !ok {
		return "", errors.New("token generate OIDC mismatch")
	}
	return token.AccessToken, nil
}

func (webToken *WebToken) OIDCContainsRoles(token string, scopes []string) (PrincipalInterface, error) {
	verifier := provider.Verifier(&oidc.Config{ClientID: oauth2Config.ClientID})

	// Parse and verify ID Token payload.
	idToken, err := verifier.Verify(context.Background(), token)
	if err != nil {
		return nil, err
	}
	fmt.Println("Check token: " + token)
	fmt.Printf("ID token %#v\n", idToken)

	// Extract custom claims
	var claims struct {
		Email    string `json:"email"`
		Verified bool   `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, err
	}
	return nil, errors.New("OIDC not implemented")
}
