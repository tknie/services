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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	errors "github.com/go-openapi/errors"
	"github.com/google/uuid"
	"github.com/tknie/log"
	"github.com/tknie/services"

	jose "github.com/go-jose/go-jose/v4"
	jwt "github.com/go-jose/go-jose/v4/jwt"
)

var (
	verifyKey2  *rsa.PublicKey
	privateKey2 *rsa.PrivateKey
)

// WebToken Web token configuration
type WebToken struct {
	Comment    string `xml:",comment" yaml:"-"`
	OAuth2     bool   `xml:"oauth2,attr" yaml:"oauth2,omitempty"`
	IssuerName string `xml:"issuer,attr" yaml:"issuer,omitempty"`
	Expirer    string `xml:"expire,attr" yaml:"expire,omitempty"`
	Encrypt    bool   `xml:"encrypt,attr" yaml:"encrypt,omitempty"`
	PublicKey  string `xml:"PublicKey" yaml:"publicKey,omitempty"`
	PrivateKey string `xml:"PrivateKey" yaml:"privateKey,omitempty"`
	PassToken  string `xml:"PassToken" yaml:"passToken,omitempty"`
}

// UserInfo user information context
type UserInfo struct {
	User          string `flynn:"Name:PRIMARY KEY"`
	EMail         string
	LongName      string
	Created       time.Time
	LastLogin     time.Time
	Picture       []byte
	Permission    *User `flynn:":YAML"`
	Administrator bool
}

// SessionInfo session information context
type SessionInfo struct {
	User        string `flynn:"Name"`
	UUID        string `flynn:"UUID:PRIMARY KEY"`
	Data        []byte
	Created     time.Time
	LastAccess  time.Time
	Invalidated time.Time
	token       interface{} `flynn:":ignore"`
}

type jsonWebTokenData struct {
	User     UserInfo
	Session  SessionInfo
	password string
	session  interface{}
	content  interface{}
}

// JWTValidate JWT validate instance
type JWTValidate interface {
	UUIDInfo(uuid string) (*SessionInfo, error)
	Range(func(uuid, value any) bool) error
	ValidateUUID(claims *JWTClaims) (PrincipalInterface, bool)
	InvalidateUUID(string, time.Time) bool
	Store(PrincipalInterface, string, string) error
}

// JWTOperator JWT operator check for UUID
var JWTOperator = JWTValidate(&DefaultJWTHandler{uuidHashStore: sync.Map{}})

// Trigger functions

// TriggerInvalidUUID trigger if UUID is invalidated
var TriggerInvalidUUID func(*SessionInfo, *UserInfo)

// JWTClaims describes the format of our JWT token's claims
type JWTClaims struct {
	UUID      string           `json:"jti,omitempty"`
	Subject   string           `json:"sub,omitempty"`
	Audience  string           `json:"aud,omitempty"`
	IAt       string           `json:"iat,omitempty"`
	Roles     []string         `json:"roles"`
	Remote    string           `json:"rem,omitempty"`
	ID        string           `json:"id,omitempty"`
	Issuer    string           `json:"iss,omitempty"`
	ExpiresAt *jwt.NumericDate `json:"exp,omitempty"`
}

// NewSessionInfo create a new Session Info instance with created and UUID filled
func NewSessionInfo(user string) *SessionInfo {
	return &SessionInfo{User: user, UUID: uuid.New().String(), Created: time.Now()}
}

// WebTokenConfig web token JWT configuration
var WebTokenConfig *WebToken
var sessionExpirerDuration = time.Duration(6) * time.Hour

var ticker *time.Ticker
var doneTicker = make(chan bool)

func init() {
	ticker = time.NewTicker(1 * time.Minute)
	go cleanUpTicker()
}

func cleanUpTicker() {
	if log.IsDebugLevel() {
		log.Log.Debugf("UUID session cleanup thread started, session expires after %v", sessionExpirerDuration)
	}
	for {
		select {
		case <-doneTicker:
			return
		case t := <-ticker.C:
			cleanUp(t)
		}
	}
}

// cleanUp start cleanup of all JWT tokens stored. It checks the elapsed time is after now.
// If it is the case, the UUID entry is deleted
func cleanUp(nowTime time.Time) {
	if WebTokenConfig != nil {
		expirer, err := time.ParseDuration(WebTokenConfig.Expirer)
		if err != nil {
		} else {
			sessionExpirerDuration = expirer
		}
		JWTOperator.Range(func(uuid, value any) bool {
			elapsed := value.(time.Time)
			if !elapsed.After(nowTime) {
				JWTOperator.InvalidateUUID(uuid.(string), elapsed)
			}
			return true
		})
	}
}

// parseRSAPrivateKeyFromPEM Parse PEM encoded PKCS1 or PKCS8 private key
func parseRSAPrivateKeyFromPEM(key []byte) (*rsa.PrivateKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, errors.New(http.StatusUnauthorized, "Invalid Key: Key must be PEM encoded PKCS1 or PKCS8 private key")
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return nil, err
		}
	}

	var pkey *rsa.PrivateKey
	var ok bool
	if pkey, ok = parsedKey.(*rsa.PrivateKey); !ok {
		return nil, errors.New(http.StatusUnauthorized, "Key is not a valid RSA private key")
	}

	return pkey, nil

}

// parseRSAPublicKeyFromPEM Parse PEM encoded PKCS1 or PKCS8 public key
func parseRSAPublicKeyFromPEM(key []byte) (*rsa.PublicKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, errors.New(http.StatusUnauthorized, "Invalid Key: Key must be PEM encoded PKCS1 or PKCS8 private key")
	}

	// Parse the key
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			parsedKey = cert.PublicKey
		} else {
			return nil, err
		}
	}

	var pkey *rsa.PublicKey
	var ok bool
	if pkey, ok = parsedKey.(*rsa.PublicKey); !ok {
		return nil, errors.New(http.StatusUnauthorized, "Key is not a valid RSA public key")
	}

	return pkey, nil
}

// InitWebTokenJose2 initialize WebToken Jose.v2 token
func (webToken *WebToken) InitWebTokenJose2() error {
	if webToken.OAuth2 {
		return webToken.InitWebTokenOIDC()
	}
	switch {
	case webToken == nil:
		return services.NewError("SYS00031")
	case webToken.PrivateKey == "":
		return services.NewError("SYS00032")
	case webToken.PublicKey == "":
		return services.NewError("SYS00033")
	}
	WebTokenConfig = webToken
	log.Log.Debugf("Init UUID hash")

	if log.IsDebugLevel() {
		log.Log.Debugf("WEBTOKEN: %v", WebTokenConfig)
	}
	WebTokenConfig = webToken

	// loads public keys to verify our tokens
	privateKeyBuf, err := os.ReadFile(os.ExpandEnv(webToken.PrivateKey))
	if err != nil {
		return services.NewError("SYS00034", webToken.PrivateKey, err)
	}
	privateKey2, err = parseRSAPrivateKeyFromPEM(privateKeyBuf)
	if err != nil {
		return services.NewError("SYS00035")
	}

	// loads public keys to verify our tokens
	verifyKeyBuf, err := os.ReadFile(os.ExpandEnv(webToken.PublicKey))
	if err != nil {
		return fmt.Errorf("cannot load public key for tokens needed for JWT")
	}
	verifyKey2, err = parseRSAPublicKeyFromPEM(verifyKeyBuf)
	if err != nil {
		return fmt.Errorf("invalid public key for tokens")
	}
	encryption := "disabled"
	if WebTokenConfig.Encrypt {
		encryption = "enabled"
	}
	services.ServerMessage("JSON Web token keys initialized, JWT encryption is %s", encryption)
	return nil
}

func uuidStore(principal PrincipalInterface, user, pass string) error {
	if principal == nil {
		return fmt.Errorf("principal configuration error")
	}
	return JWTOperator.Store(principal, user, pass)
}

// GenerateJWToken generate JWT token using golang Jose.v2
func (webToken *WebToken) GenerateJWToken(IAt string, principal PrincipalInterface) (tokenString string, err error) {
	if webToken == nil {
		return "", fmt.Errorf("web token not configured properly")
	}
	if webToken.OAuth2 {
		return webToken.generateOIDCToken(IAt, principal)
	}
	token, err := generateCallbackToken(IAt, principal)
	if err == nil {
		return token, err
	}

	claim := JWTClaims{Roles: principal.Roles(), ID: principal.Name(), Subject: "RestServer", IAt: IAt}
	if log.IsDebugLevel() {
		log.Log.Debugf("Generate token -> Principal %s: %#v", principal.Name(), principal.Roles())
	}
	claim.UUID = principal.UUID()
	claim.ExpiresAt = jwt.NewNumericDate(time.Now().Add(sessionExpirerDuration))
	claim.Issuer = webToken.IssuerName
	claim.Remote = principal.Remote()
	if webToken.Encrypt {
		enc, err := jose.NewEncrypter(
			jose.A128GCM,
			jose.Recipient{Algorithm: jose.RSA1_5, Key: verifyKey2},
			(&jose.EncrypterOptions{}).WithType("JWT"),
		)
		if err != nil {
			log.Log.Debugf("Error create encrypter %v", err)
			return "", err
		}
		tokenString, err = jwt.Encrypted(enc).Claims(claim).Serialize()
		if err != nil {
			log.Log.Debugf("Error create encrypted token: %v", err)
			return "", err
		}
	} else {
		signer, err := jose.NewSigner(
			jose.SigningKey{Algorithm: jose.PS512, Key: privateKey2},
			nil,
		)
		if err != nil {
			return "", err
		}
		tokenString, err = jwt.Signed(signer).Claims(claim).Serialize()
		if err != nil {
			log.Log.Debugf("Error create signed token: %v", err)
			return "", err
		}
	}
	uuidStore(principal, principal.Name(), "")
	return tokenString, nil
}

// parseAndCheckToken2 parse and check token with Jose.v2
// use decrypt or signature check if configured
func (webToken *WebToken) parseAndCheckToken2(token string) (*JWTClaims, error) {
	if webToken.Encrypt {
		tok, err := jose.ParseEncrypted(token, []jose.KeyAlgorithm{jose.RSA1_5}, []jose.ContentEncryption{jose.A128GCM})
		if err != nil {
			return nil, err
		}
		x, decErr := tok.Decrypt(privateKey2)
		if decErr != nil {
			return nil, decErr
		}
		out := &JWTClaims{}
		err = json.Unmarshal(x, out)
		if err != nil {
			return nil, err
		}
		return out, nil
	}
	tok, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.PS512})
	if err != nil {
		return nil, err
	}
	x, signErr := tok.Verify(verifyKey2)
	if signErr != nil {
		return nil, signErr
	}
	out := &JWTClaims{}
	err = json.Unmarshal(x, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// JWTContainsRoles tells if the Bearer token is a JWT signed by us with a claim to be
// member of an authorization scope.
// We verify that the claimed role is one of the passed scopes and if the UUID is stored and valid.
func (webToken *WebToken) JWTContainsRoles(token string, scopes []string) (PrincipalInterface, error) {
	if log.IsDebugLevel() {
		log.Log.Debugf("Has role scopes %#v", scopes)
	}
	if webToken.OAuth2 {
		return webToken.checkOIDCContainsRoles(token, scopes)
	}
	if webToken.PassToken != "" && token == webToken.PassToken {
		si := &SessionInfo{UUID: webToken.PassToken}
		p := PrincipalCreater(si, "XXXX", "")
		return p, nil

	}
	p, err := checkCallbackToken(token, scopes)
	if err == nil {
		return p, err
	}
	claims, err := webToken.parseAndCheckToken2(token)
	if err == nil {
		if log.IsDebugLevel() {
			log.Log.Debugf("Claims %#v", claims)
		}
		issuer := "Unknown"
		if WebTokenConfig != nil {
			issuer = WebTokenConfig.IssuerName
		}
		if claims.Issuer == issuer {
			// isInScopes := false
			//claimedRoles := []string{}
			isInScopes := checkInScope(scopes, claims.Roles)

			if !isInScopes {
				if log.IsDebugLevel() {
					log.Log.Debugf("Role error", claims.UUID)
				}
				services.ServerMessage(fmt.Sprintf("Unauthorized token (Role error): %v", claims.UUID))
				return nil, errors.New(http.StatusUnauthorized, "Unauthorized.")
			}
			if log.IsDebugLevel() {
				log.Log.Debugf("Is in scope: %v", isInScopes)
			}
			if p, ok := validUUID(claims); ok {
				return p, nil
			}
			if log.IsDebugLevel() {
				log.Log.Debugf("UUID %s not found for %s", claims.UUID, claims.ID)
			}
			services.ServerMessage("Token error, UUID %s token not found (%s/%s)", claims.UUID, issuer, claims.ID)
			return nil, errors.New(http.StatusUnauthorized, "unauthorized...token not found for %s/%s", claims.UUID, claims.ID)
		}
		if log.IsDebugLevel() {
			log.Log.Debugf("Issuer error: %s != %s", claims.Issuer, issuer)
		}
		services.ServerMessage("Unauthorized token (Issuer error): %s (%s)", WebTokenConfig.IssuerName, claims.ID)
		return nil, errors.New(http.StatusUnauthorized, "unauthorized...issuer incorrect for %s/%s", claims.UUID, claims.ID)
	}
	if log.IsDebugLevel() {
		log.Log.Debugf("Claim error")
	}
	services.ServerMessage("Unauthorized token (Claim error): %v", err)

	return nil, errors.New(http.StatusUnauthorized, "Unauthorized: invalid Bearer token: %v", err)
}

func checkInScope(scopes, roles []string) bool {
	for _, scope := range scopes {
		for _, role := range roles {
			if log.IsDebugLevel() {
				log.Log.Debugf("Check role %v in scope %v", role, scope)
			}
			if role == scope {
				// isInScopes = true
				// we enrich the principal with all claimed roles within scope (hence: not breaking here)
				//claimedRoles = append(claimedRoles, role)
				return true
			}
		}
	}
	return false
}

func validUUID(claims *JWTClaims) (PrincipalInterface, bool) {
	return JWTOperator.ValidateUUID(claims)
}

// InvalidateUUID invalidate UUID not valid any more
func InvalidateUUID(uuid string, elapsed time.Time) bool {
	return JWTOperator.InvalidateUUID(uuid, elapsed)
}

// UUIDInfo get UUID info User information
func UUIDInfo(uuid string) (*SessionInfo, error) {
	return JWTOperator.UUIDInfo(uuid)
}

// EncryptData encrypt data to base64 string
func EncryptData(data string) (string, error) {
	hash := sha512.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, &privateKey2.PublicKey, []byte(data), nil)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptData decsrypt base64 data to string
func DecryptData(token string) (string, error) {
	hash := sha512.New()
	data, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return "", err
	}
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, privateKey2, data, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
