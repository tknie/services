/*
* Copyright 2022-2025 Thorsten A. Knieling
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
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/tknie/log"
	"golang.org/x/oauth2"
)

var oauth2Config *oauth2.Config
var provider *oidc.Provider

type claimsJSON struct {
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
		log.Log.Debugf("no OIDC client config given during init")
		return errors.New("no OIDC client config given")
	}
	clientID := os.ExpandEnv(auth.ClientID)
	clientSecret := os.ExpandEnv(auth.ClientSecret)
	url := os.ExpandEnv(auth.URL)
	if clientID == "" || clientSecret == "" || url == "" {
		log.Log.Debugf("no OIDC client config details given")
		return errors.New("no OIDC client config details given")
	}
	var err error
	provider, err = oidc.NewProvider(context.Background(), url)
	if err != nil {
		log.Log.Debugf("Provider error: %s", err)
		return err
	}

	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		// RedirectURL:  OIDCClient.RedirectURL,

		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}
	log.Log.Debugf("OIDC initialized for client ID = %s", clientID)
	return nil
}

// callbackOIDCAuthenticate authenticate user and password to OIDC client
func callbackOIDCAuthenticate(auth *AuthenticationServer, principal PrincipalInterface, userName, passwd string) error {
	if oauth2Config == nil {
		log.Log.Debugf("no OIDC client config given during authenticate")
		return errors.New("no OIDC configured")
	}
	token, err := oauth2Config.PasswordCredentialsToken(context.Background(), userName, passwd)
	if err != nil {
		log.Log.Debugf("OIDC Password token check fails: %v", err)
		return err
	}
	principal.SetRemote(auth.URL)
	principal.SetSession(&SessionInfo{User: userName, UUID: uuid.New().String(), token: token})
	log.Log.Debugf("User %s authenticate successfully using OIDC", userName)
	return nil
}

// InitWebTokenOIDC init web token for OIDC
func (webToken *WebToken) InitWebTokenOIDC() error {
	return nil
}

// generateOIDCToken generate OIDC token using OAuth2 web instance
func (webToken *WebToken) generateOIDCToken(IAt string, principal PrincipalInterface) (tokenString string, err error) {
	session, ok := principal.Session().(*SessionInfo)
	if !ok {
		return "", errors.New("session memory entry OIDC mismatch")
	}
	token, ok := session.token.(*oauth2.Token)
	if !ok {
		return "", errors.New("token memory entry OIDC mismatch")
	}
	log.Log.Debugf("Access token: %s", token.AccessToken)
	return token.AccessToken, nil
}

// checkOIDCContainsRoles OIDCS check for roles
func (webToken *WebToken) checkOIDCContainsRoles(token string, scopes []string) (PrincipalInterface, error) {
	if oauth2Config == nil {
		log.Log.Debugf("no OIDC client config given during check")
		return nil, errors.New("no OIDC config configured")
	}
	if provider == nil {
		log.Log.Debugf("no OIDC client provider given during check")
		return nil, errors.New("no OIDC provider configured")
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: oauth2Config.ClientID})

	log.Log.Debugf("Verify OIDC token: %s", token)
	// Parse and verify ID Token payload.
	idToken, err := verifier.Verify(context.Background(), token)
	if err != nil {
		log.Log.Debugf("Verify error: %v", err)
		return nil, err
	}
	log.Log.Debugf("ID token %#v", idToken)

	// Extract custom claims
	claims := &claimsJSON{}
	if err := idToken.Claims(claims); err != nil {
		log.Log.Debugf("Verify error evaluating claims: %v", err)
		return nil, err
	}
	log.Log.Debugf("Claims %#v", claims)
	p := PrincipalCreater(&SessionInfo{User: claims.EMail, UUID: uuid.New().String(), token: idToken},
		claims.EMail, token)
	log.Log.Debugf("Scope check %#v ignored, OIDC check ok", scopes)
	return p, nil
}
