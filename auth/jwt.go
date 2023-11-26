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
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	errors "github.com/go-openapi/errors"
	"github.com/tknie/log"
	"github.com/tknie/services"

	jose "gopkg.in/square/go-jose.v2"
	jwt "gopkg.in/square/go-jose.v2/jwt"
)

var (
	verifyKey2  *rsa.PublicKey
	privateKey2 *rsa.PrivateKey
)

// WebToken Web token configuration
type WebToken struct {
	Comment    string `xml:",comment" yaml:"-"`
	IssuerName string `xml:"issuer,attr" yaml:"issuer,omitempty"`
	Expirer    string `xml:"expire,attr" yaml:"expire,omitempty"`
	Encrypt    bool   `xml:"encrypt,attr" yaml:"encrypt,omitempty"`
	PublicKey  string `xml:"PublicKey" yaml:"publicKey,omitempty"`
	PrivateKey string `xml:"PrivateKey" yaml:"privateKey,omitempty"`
	PassToken  string `xml:"PassToken" yaml:"passToken,omitempty"`
}

// UserInfo user information context
type UserInfo struct {
	UUID     string
	User     string
	Picture  string
	EMail    string
	LongName string
	Created  time.Time
}

type jsonWebTokenData struct {
	User     UserInfo
	password string
	session  interface{}
	content  interface{}
}

var uuidHashStore = sync.Map{}

// Trigger functions

// TriggerInvalidUUID trigger if UUID is invalidated
var TriggerInvalidUUID func(*UserInfo)

// roleClaims describes the format of our JWT token's claims
type roleClaimsJose2 struct {
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

// WebTokenConfig web token JWT configuration
var WebTokenConfig *WebToken
var sessionExpirerDuration = time.Duration(6) * time.Hour

// var privateKeyJose2 *jose.JSONWebSignature
// var rsaPrivateKeyPassword = ""
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
		uuidHashStore.Range(func(uuid, value any) bool {
			authData := value.(*jsonWebTokenData)
			elapsed := authData.User.Created.Add(sessionExpirerDuration)
			if !elapsed.After(nowTime) {
				InvalidateUUID(uuid.(string), elapsed)
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
	switch {
	case webToken == nil:
		return fmt.Errorf("instance not defined")
	case webToken.PrivateKey == "":
		return fmt.Errorf("private key path not defined")
	case webToken.PublicKey == "":
		return fmt.Errorf("public key path not defined")
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
		return fmt.Errorf("cannot load private key for tokens needed for JWT %s: %v", webToken.PrivateKey, err)
	}
	privateKey2, err = parseRSAPrivateKeyFromPEM(privateKeyBuf)
	if err != nil {
		return fmt.Errorf("invalid private key for tokens")
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

func uuidStore(principal PrincipalInterface, user, pass string) {
	if principal == nil {
		return
	}
	log.Log.Infof("Adding UUID %s create %v", principal.UUID(), time.Now())
	uuidHashStore.Store(principal.UUID(), &jsonWebTokenData{User: UserInfo{UUID: principal.UUID(),
		User: user, Created: time.Now()}, password: pass, content: principal,
		session: principal.Session()})
}

// GenerateJWToken generate JWT token using golang Jose.v2
func (webToken *WebToken) GenerateJWToken(IAt string, principal PrincipalInterface) (tokenString string, err error) {
	if webToken == nil {
		return "", fmt.Errorf("web token not configured properly")
	}
	token, err := generateCallbackToken(IAt, principal)
	if err == nil {
		return token, err
	}

	claim := roleClaimsJose2{Roles: principal.Roles(), ID: principal.Name(), Subject: "RestServer", IAt: IAt}
	if log.IsDebugLevel() {
		log.Log.Debugf("Generate token -> Principal %s: %#v", principal.Name(), principal.Roles())
	}
	claim.UUID = principal.UUID()
	claim.ExpiresAt = jwt.NewNumericDate(time.Now().Add(sessionExpirerDuration))
	if webToken != nil {
		claim.Issuer = webToken.IssuerName
	} else {
		claim.Issuer = "Unknown"
	}
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
		tokenString, err = jwt.Encrypted(enc).Claims(claim).CompactSerialize()
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
		tokenString, err = jwt.Signed(signer).Claims(claim).CompactSerialize()
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
func (webToken *WebToken) parseAndCheckToken2(token string) (*roleClaimsJose2, error) {
	if webToken.Encrypt {
		tok, err := jose.ParseEncrypted(token)
		if err != nil {
			return nil, err
		}
		x, decErr := tok.Decrypt(privateKey2)
		if decErr != nil {
			return nil, decErr
		}
		out := &roleClaimsJose2{}
		err = json.Unmarshal(x, out)
		if err != nil {
			return nil, err
		}
		return out, nil
	}
	tok, err := jose.ParseSigned(token)
	if err != nil {
		return nil, err
	}
	x, signErr := tok.Verify(verifyKey2)
	if signErr != nil {
		return nil, signErr
	}
	out := &roleClaimsJose2{}
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
	if webToken.PassToken != "" && token == webToken.PassToken {
		p := PrincipalCreater(webToken.PassToken, "XXXX", "")
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
			isInScopes := false
			//claimedRoles := []string{}
			for _, scope := range scopes {
				for _, role := range claims.Roles {
					if log.IsDebugLevel() {
						log.Log.Debugf("Check role %v in scope %v", role, scope)
					}
					if role == scope {
						isInScopes = true
						// we enrich the principal with all claimed roles within scope (hence: not breaking here)
						//claimedRoles = append(claimedRoles, role)
					}
				}
			}
			if !isInScopes {
				if log.IsDebugLevel() {
					log.Log.Debugf("Role error", claims.UUID)
				}
				services.ServerMessage(fmt.Sprintf("Unauthorized token (Role error): %v", err))
				return nil, errors.New(http.StatusUnauthorized, "Unauthorized.")
			}
			if log.IsDebugLevel() {
				log.Log.Debugf("Is in scope: %v", isInScopes)
			}
			if p, ok := validUUID(claims); ok {
				return p, nil
			}
			if claims.IAt == "<pass>" {
				services.ServerMessage(fmt.Sprintf("Token passed and UUID created: %s", claims.ID))
				uuidHashStore.Store(claims.UUID, &jsonWebTokenData{User: UserInfo{UUID: claims.UUID,
					User: claims.ID, Created: time.Now()}, password: ""})
				p := PrincipalCreater(claims.UUID, claims.ID, "")
				p.SetRemote(claims.Remote)
				p.AddRoles(claims.Roles)
				return p, nil
			}
			if log.IsDebugLevel() {
				log.Log.Debugf("UUID %s not found for %s", claims.UUID, claims.ID)
			}
			services.ServerMessage("Token error, UUID %s token not found (%s/%s)", claims.UUID, issuer, claims.ID)
			return nil, errors.New(http.StatusUnauthorized, "Unauthorized...token not found for "+claims.UUID+" / "+claims.ID)
		}
		if log.IsDebugLevel() {
			log.Log.Debugf("Issuer error: %s != %s", claims.Issuer, issuer)
		}
		services.ServerMessage("Unauthorized token (Issuer error): %s (%s)", WebTokenConfig.IssuerName, claims.ID)
		return nil, errors.New(http.StatusUnauthorized, "Unauthorized...issuer incorrect for "+claims.UUID+" / "+claims.ID)
	} else {
		if log.IsDebugLevel() {
			log.Log.Debugf("Claim error")
		}
		services.ServerMessage("Unauthorized token (Claim error): %v", err)
	}
	return nil, errors.New(http.StatusUnauthorized, "Unauthorized: invalid Bearer token: %v", err)
}

func validUUID(claims *roleClaimsJose2) (PrincipalInterface, bool) {
	if v, ok := uuidHashStore.Load(claims.UUID); ok {
		auth := v.(*jsonWebTokenData)
		var p PrincipalInterface
		if auth.content != nil {
			p = auth.content.(PrincipalInterface)
		} else {
			p = PrincipalCreater(auth.User.UUID, auth.User.User, auth.password)
			p.SetRemote(claims.Remote)
			p.SetSession(auth.session)
			p.AddRoles(claims.Roles)
		}
		log.Log.Debugf("Create JWT principal: %p", p)
		// if p.Session == nil {
		// 	p.Session = admin.CreateSession(auth.user, auth.password)
		// }
		return p, true
	}
	return nil, false
}

// InvalidateUUID invalidate UUID not valid any more
func InvalidateUUID(uuid string, elapsed time.Time) bool {
	if v, ok := uuidHashStore.LoadAndDelete(uuid); ok {
		tokenData := v.(*jsonWebTokenData)
		log.Log.Infof("Remove expired UUID %s at %v", uuid, elapsed)
		services.ServerMessage("UUID %s expired for user %s",
			uuid, tokenData.User.User)
		user := &UserInfo{}
		*user = tokenData.User
		TriggerInvalidUUID(user)
		return true
	}
	return false
}

// UUIDInfo get UUID info User information
func UUIDInfo(uuid string) *UserInfo {
	if v, ok := uuidHashStore.Load(uuid); ok {
		tokenData := v.(*jsonWebTokenData)
		user := &UserInfo{}
		*user = tokenData.User
		TriggerInvalidUUID(user)
		return user
	}
	return nil

}
