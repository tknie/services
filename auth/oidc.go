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

	"github.com/coreos/go-oidc"
	"github.com/tknie/log"
	"golang.org/x/oauth2"
)

var oauth2Config *oauth2.Config
var provider *oidc.Provider

type claimsJson struct {
	Expiry            int32  `json:"exp"`
	IssuedAt          int32  `json:"iat"`
	JTI               string `json:"jti"`
	ISS               string `json:"iss"`
	AUD               string `json:"aud"`
	Sub               string `json:"sub"`
	TYP               string `json:"typ"`
	AZP               string `json:"azp"`
	SessionState      string `json:"session_state"`
	ACR               string `json:"acr"`
	SID               string `json:"sid"`
	EMailVerified     bool   `json:"email_verified"`
	Name              string `json:"name"`
	LastAuth          int32  `json:"last_auth"`
	PreferredUsername string `json:"preferred_username"`
	GivenName         string `json:"given_name"`
	FamilyName        string `json:"family_name"`
	EMail             string `json:"email"`
}

// InitOIDC initialize basic parameters for OIDCS authentication
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
	principal.SetRemote(auth.URL)
	principal.SetSession(token)
	return nil
}

// InitWebTokenOIDC init web token for OIDC
func (webToken *WebToken) InitWebTokenOIDC() error {
	return nil
}

// generateOIDCToken generate OIDC token using OAuth2 web instance
func (webToken *WebToken) generateOIDCToken(IAt string, principal PrincipalInterface) (tokenString string, err error) {
	token, ok := principal.Session().(*oauth2.Token)
	if !ok {
		return "", errors.New("token generate OIDC mismatch")
	}
	return token.AccessToken, nil
}

// checkOIDCContainsRoles OIDCS check for roles
func (webToken *WebToken) checkOIDCContainsRoles(token string, scopes []string) (PrincipalInterface, error) {
	verifier := provider.Verifier(&oidc.Config{ClientID: oauth2Config.ClientID})

	// Parse and verify ID Token payload.
	idToken, err := verifier.Verify(context.Background(), token)
	if err != nil {
		return nil, err
	}
	log.Log.Debugf("Check token: " + token)
	log.Log.Debugf("ID token %#v", idToken)

	// Extract custom claims
	claims := &claimsJson{}
	if err := idToken.Claims(claims); err != nil {
		return nil, err
	}
	log.Log.Debugf("Claims %#v", claims)
	p := PrincipalCreater(&SessionInfo{User: claims.EMail, UUID: claims.SID},
		claims.EMail, token)
	return p, nil
}
