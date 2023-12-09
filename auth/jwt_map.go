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
	"sync"
	"time"

	"github.com/tknie/log"
	"github.com/tknie/services"
)

// DefaultJWTHandler default local Map instance
type DefaultJWTHandler struct {
	uuidHashStore sync.Map
}

// UUIDInfo get UUID info User information
func (df *DefaultJWTHandler) UUIDInfo(uuid string) *UserInfo {
	if v, ok := df.uuidHashStore.Load(uuid); ok {
		tokenData := v.(*jsonWebTokenData)
		user := &UserInfo{}
		*user = tokenData.User
		TriggerInvalidUUID(&tokenData.Session, &tokenData.User)
		return user
	}
	return nil

}

// Range go through all session entries
func (df *DefaultJWTHandler) Range(f func(uuid, value any) bool) {
	df.uuidHashStore.Range(f)
}

// InvalidateUUID invalidate UUID entry and given elapsed time
func (df *DefaultJWTHandler) InvalidateUUID(uuid string, elapsed time.Time) bool {
	if v, ok := df.uuidHashStore.LoadAndDelete(uuid); ok {
		tokenData := v.(*jsonWebTokenData)
		log.Log.Infof("Remove expired UUID %s at %v", uuid, elapsed)
		services.ServerMessage("UUID %s expired for user %s",
			uuid, tokenData.User.User)
		user := &UserInfo{}
		*user = tokenData.User
		TriggerInvalidUUID(&tokenData.Session, &tokenData.User)
		return true
	}
	return false
}

// Store store entry for given input
func (df *DefaultJWTHandler) Store(principal PrincipalInterface, user, pass string) {
	created := time.Now()
	log.Log.Infof("Adding UUID %s create %v", principal.UUID(), created)
	df.uuidHashStore.Store(principal.UUID(),
		&jsonWebTokenData{Session: SessionInfo{UUID: principal.UUID(), Created: created},
			User:     UserInfo{User: user, Created: created},
			password: pass, content: principal,
			session: principal.Session()})

}

// ValidateUUID validate JWT claims are in UUID session list
func (df *DefaultJWTHandler) ValidateUUID(claims *JWTClaims) (PrincipalInterface, bool) {
	if claims.IAt == "<pass>" {
		services.ServerMessage(fmt.Sprintf("Token passed and UUID created: %s", claims.ID))
		created := time.Now()
		jwtd := &jsonWebTokenData{Session: SessionInfo{UUID: claims.UUID, Created: created},
			User: UserInfo{User: claims.ID, Created: created}, password: ""}
		df.uuidHashStore.Store(claims.UUID, jwtd)
		p := PrincipalCreater(&jwtd.Session, claims.ID, "")
		p.SetRemote(claims.Remote)
		p.AddRoles(claims.Roles)
		return p, true
	}
	if v, ok := df.uuidHashStore.Load(claims.UUID); ok {
		auth := v.(*jsonWebTokenData)
		var p PrincipalInterface
		if auth.content != nil {
			p = auth.content.(PrincipalInterface)
		} else {
			p = PrincipalCreater(&auth.Session, auth.User.User, auth.password)
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
