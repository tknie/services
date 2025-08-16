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
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/tknie/log"
)

// SecurityProtocol integer protocol type
type SecurityProtocol int

// Note: new type must be added at the end of list to maintain compatibility.
const (
	SecurityProtocolUnencrypted SecurityProtocol = iota
	SecurityProtocolLDAPS
	SecurityProtocolStartTLS
)

// Source Basic LDAP authentication service
type Source struct {
	Name              string // canonical name (ie. corporate.ad)
	Host              string // LDAP host
	Port              int    // port number
	SecurityProtocol  SecurityProtocol
	SkipVerify        bool   `xml:"skipVerify,attr"`
	BindDN            string // DN to bind with
	BindPassword      string // Bind DN password
	UserBase          string // Base search path for users
	UserDN            string // Template for the DN of the user for simple auth
	AttributeUsername string // Username attribute
	AttributeName     string // First name attribute
	AttributeSurname  string // Surname attribute
	AttributeMail     string // E-mail attribute
	AttributesInBind  bool   `xml:"attributesInBind,attr"` // fetch attributes in bind context (not user)
	SearchPageSize    uint32 // Search with paging page size
	Filter            string // Query filter to validate entry
	AdminFilter       string // Query filter to check if user is admin
	RestrictedFilter  string // Query filter to check if user is restricted
	Enabled           bool   `xml:"-"`                  // if this source is disabled
	GroupsEnabled     bool   `xml:"groupsEnabled,attr"` // if the group checking is enabled
	GroupDN           string // Group Search Base
	GroupFilter       string // Group Name Filter
	GroupMemberUID    string // Group Attribute containing array of UserUID
	UserUID           string // User Attribute listed in Group
}

// SearchResult : user data
type SearchResult struct {
	Username     string // Username
	Name         string // Name
	Surname      string // Surname
	Mail         string // E-mail address
	IsAdmin      bool   // if user is administrator
	IsRestricted bool   // if user is restricted
}

func (src *Source) sanitizedUserQuery(username string) (string, bool) {
	// See http://tools.ietf.org/search/rfc4515
	badCharacters := "\x00()*\\"
	if strings.ContainsAny(username, badCharacters) {
		log.Log.Debugf("'%s' contains invalid query characters. Aborting.", username)
		return "", false
	}

	return fmt.Sprintf(src.Filter, username), true
}

func (src *Source) sanitizedUserDN(username string) (string, bool) {
	// See http://tools.ietf.org/search/rfc4514: "special characters"
	badCharacters := "\x00()*\\,='\"#+;<>"
	if strings.ContainsAny(username, badCharacters) {
		log.Log.Debugf("'%s' contains invalid DN characters. Aborting.", username)
		return "", false
	}

	return fmt.Sprintf(src.UserDN, username), true
}

func (src *Source) sanitizedGroupFilter(group string) (string, bool) {
	// See http://tools.ietf.org/search/rfc4515
	badCharacters := "\x00*\\"
	if strings.ContainsAny(group, badCharacters) {
		log.Log.Debugf("Group filter invalid query characters: %s", group)
		return "", false
	}

	return group, true
}

func (src *Source) sanitizedGroupDN(groupDn string) (string, bool) {
	// See http://tools.ietf.org/search/rfc4514: "special characters"
	badCharacters := "\x00()*\\'\"#+;<>"
	if strings.ContainsAny(groupDn, badCharacters) || strings.HasPrefix(groupDn, " ") || strings.HasSuffix(groupDn, " ") {
		log.Log.Debugf("Group DN contains invalid query characters: %s", groupDn)
		return "", false
	}

	return groupDn, true
}

func (src *Source) findUserDN(l *ldap.Conn, name string) (string, bool, error) {
	log.Log.Debugf("Search for LDAP user: %s", name)

	// A search for the user.
	userFilter, ok := src.sanitizedUserQuery(name)
	if !ok {
		return "", false, fmt.Errorf("sanitize user query %s", name)
	}

	log.Log.Debugf("Searching for DN using filter %s and base %s", userFilter, src.UserBase)
	search := ldap.NewSearchRequest(
		src.UserBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0,
		false, userFilter, []string{}, nil)

	// Ensure we found a user
	sr, err := l.Search(search)
	if err != nil || len(sr.Entries) < 1 {
		log.Log.Errorf("Failed search using filter[%s]: %v", userFilter, err)
		return "", false, err
	} else if len(sr.Entries) > 1 {
		log.Log.Debugf("Filter '%s' returned more than one user.", userFilter)
		return "", false, fmt.Errorf("filter don't return unique entry")
	}

	userDN := sr.Entries[0].DN
	if userDN == "" {
		log.Log.Errorf("LDAP search was successful, but found no DN!")
		return "", false, fmt.Errorf("no DN found")
	}

	return userDN, true, nil
}

func dial(ls *Source) (*ldap.Conn, error) {
	log.Log.Debugf("Dialing LDAP with security protocol (%v) without verifying: %v", ls.SecurityProtocol, ls.SkipVerify)

	tlsCfg := &tls.Config{
		ServerName:         ls.Host,
		InsecureSkipVerify: ls.SkipVerify,
	}
	if ls.SecurityProtocol == SecurityProtocolLDAPS {
		return ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", ls.Host, ls.Port), tlsCfg)
	}

	conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", ls.Host, ls.Port))
	if err != nil {
		return nil, fmt.Errorf("dial: %v", err)
	}

	if ls.SecurityProtocol == SecurityProtocolStartTLS {
		if err = conn.StartTLS(tlsCfg); err != nil {
			conn.Close()
			return nil, fmt.Errorf("StartTLS: %v", err)
		}
	}

	return conn, nil
}

func bindUser(l *ldap.Conn, userDN, passwd string) error {
	log.Log.Debugf("Binding with userDN: %s", userDN)
	err := l.Bind(userDN, passwd)
	if err != nil {
		log.Log.Debugf("LDAP auth. failed for %s, reason: %v", userDN, err)
		return err
	}
	log.Log.Debugf("Bound successfully with userDN: %s", userDN)
	return err
}

func checkAdmin(l *ldap.Conn, ls *Source, userDN string) bool {
	if len(ls.AdminFilter) == 0 {
		return false
	}
	log.Log.Debugf("Checking admin with filter %s and base %s", ls.AdminFilter, userDN)
	search := ldap.NewSearchRequest(
		userDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, ls.AdminFilter,
		[]string{ls.AttributeName},
		nil)

	sr, err := l.Search(search)

	if err != nil {
		log.Log.Errorf("LDAP Admin Search failed unexpectedly! (%v)", err)
	} else if len(sr.Entries) < 1 {
		log.Log.Debugf("LDAP Admin Search found no matching entries.")
	} else {
		return true
	}
	return false
}

func checkRestricted(lConn *ldap.Conn, ls *Source, userDN string) bool {
	if len(ls.RestrictedFilter) == 0 {
		return false
	}
	if ls.RestrictedFilter == "*" {
		return true
	}
	log.Log.Debugf("Checking restricted with filter %s and base %s", ls.RestrictedFilter, userDN)
	search := ldap.NewSearchRequest(
		userDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, ls.RestrictedFilter,
		[]string{ls.AttributeName},
		nil)

	sr, err := lConn.Search(search)

	if err != nil {
		log.Log.Errorf("LDAP Restrictred Search failed unexpectedly! (%v)", err)
	} else if len(sr.Entries) < 1 {
		log.Log.Debugf("LDAP Restricted Search found no matching entries.")
	} else {
		return true
	}
	return false
}

// SearchEntry : search an LDAP source if an entry (name, passwd) is valid and in the specific filter
func (src *Source) SearchEntry(name, passwd string, directBind bool) (*SearchResult, error) {
	log.Log.Debugf("Search LDAP entry %#v", src)
	// See https://tools.ietf.org/search/rfc4513#section-5.1.2
	if len(passwd) == 0 {
		log.Log.Debugf("Auth. failed for %s, password cannot be empty", name)
		return nil, fmt.Errorf("password empty")
	}
	lConn, err := dial(src)
	if err != nil {
		log.Log.Errorf("LDAP Connect error, %s:%v", src.Host, err)
		src.Enabled = false
		return nil, err
	}
	defer lConn.Close()

	var userDN string
	if directBind {
		log.Log.Debugf("LDAP will bind directly via UserDN template: %s", src.UserDN)

		var ok bool
		userDN, ok = src.sanitizedUserDN(name)

		if !ok {
			return nil, fmt.Errorf("sanitize User DN error")
		}

		err = bindUser(lConn, userDN, passwd)
		if err != nil {
			return nil, err
		}

		if src.UserBase != "" {
			// not everyone has a CN compatible with input name so we need to find
			// the real userDN in that case

			userDN, ok, err = src.findUserDN(lConn, name)
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, fmt.Errorf("find user DN error: %s", name)
			}
		}
	} else {
		log.Log.Debugf("LDAP will use BindDN.")

		if src.BindDN != "" && src.BindPassword != "" {
			err := lConn.Bind(src.BindDN, src.BindPassword)
			if err != nil {
				log.Log.Debugf("Failed to bind as BindDN[%s]: %v", src.BindDN, err)
				return nil, err
			}
			log.Log.Debugf("Bound as BindDN %s", src.BindDN)
		} else {
			log.Log.Debugf("Proceeding with anonymous LDAP search.")
		}

		var found bool
		userDN, found, err = src.findUserDN(lConn, name)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("not found any User DN %s", name)
		}
	}

	if !src.AttributesInBind {
		// binds user (checking password) before looking-up attributes in user context
		err = bindUser(lConn, userDN, passwd)
		if err != nil {
			return nil, err
		}
	}

	userFilter, ok := src.sanitizedUserQuery(name)
	if !ok {
		return nil, fmt.Errorf("sanitize user query error")
	}

	attribs := []string{src.AttributeUsername, src.AttributeName, src.AttributeSurname, src.AttributeMail}
	if len(strings.TrimSpace(src.UserUID)) > 0 {
		attribs = append(attribs, src.UserUID)
	}

	log.Log.Debugf("Fetching attributes '%v', '%v', '%v', '%v',  '%v' with filter '%s' and base '%s'", src.AttributeUsername, src.AttributeName, src.AttributeSurname, src.AttributeMail, src.UserUID, userFilter, userDN)
	search := ldap.NewSearchRequest(
		userDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, userFilter,
		attribs, nil)

	sr, err := lConn.Search(search)
	if err != nil {
		log.Log.Errorf("LDAP Search failed unexpectedly! (%v)", err)
		return nil, err
	} else if len(sr.Entries) < 1 {
		if directBind {
			log.Log.Debugf("User filter inhibited user login.")
		} else {
			log.Log.Debugf("LDAP Search found no matching entries.")
		}

		return nil, fmt.Errorf("LDAP search no entries")
	}

	username := sr.Entries[0].GetAttributeValue(src.AttributeUsername)
	firstname := sr.Entries[0].GetAttributeValue(src.AttributeName)
	surname := sr.Entries[0].GetAttributeValue(src.AttributeSurname)
	mail := sr.Entries[0].GetAttributeValue(src.AttributeMail)
	uid := sr.Entries[0].GetAttributeValue(src.UserUID)

	// Check group membership
	if src.GroupsEnabled {
		groupFilter, ok := src.sanitizedGroupFilter(src.GroupFilter)
		if !ok {
			return nil, fmt.Errorf("error sanitized group filter")
		}
		groupDN, ok := src.sanitizedGroupDN(src.GroupDN)
		if !ok {
			return nil, fmt.Errorf("error sanitized group DN")
		}

		log.Log.Debugf("Fetching groups '%v' with filter '%s' and base '%s'", src.GroupMemberUID, groupFilter, groupDN)
		groupSearch := ldap.NewSearchRequest(
			groupDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, groupFilter,
			[]string{src.GroupMemberUID},
			nil)

		srg, err := lConn.Search(groupSearch)
		if err != nil {
			log.Log.Errorf("LDAP group search failed: %v", err)
			return nil, err
		} else if len(srg.Entries) < 1 {
			log.Log.Errorf("LDAP group search failed: 0 entries")
			return nil, fmt.Errorf("error group search empty")
		}

		isMember := false
	Entries:
		for _, group := range srg.Entries {
			for _, member := range group.GetAttributeValues(src.GroupMemberUID) {
				if (src.UserUID == "dn" && member == sr.Entries[0].DN) || member == uid {
					isMember = true
					break Entries
				}
			}
		}

		if !isMember {
			log.Log.Errorf("LDAP group membership test failed")
			return nil, fmt.Errorf("is no member")
		}
	}

	isAdmin := checkAdmin(lConn, src, userDN)
	var isRestricted bool
	if !isAdmin {
		isRestricted = checkRestricted(lConn, src, userDN)
	}

	if !directBind && src.AttributesInBind {
		// binds user (checking password) after looking-up attributes in BindDN context
		err = bindUser(lConn, userDN, passwd)
		if err != nil {
			return nil, err
		}
	}

	return &SearchResult{
		Username:     username,
		Name:         firstname,
		Surname:      surname,
		Mail:         mail,
		IsAdmin:      isAdmin,
		IsRestricted: isRestricted,
	}, nil
}

// UsePagedSearch returns if need to use paged search
func (src *Source) UsePagedSearch() bool {
	return src.SearchPageSize > 0
}

// SearchEntries : search an LDAP source for all users matching userFilter
func (src *Source) SearchEntries() ([]*SearchResult, error) {
	lConn, err := dial(src)
	if err != nil {
		log.Log.Errorf("LDAP Connect error, %s:%v", src.Host, err)
		src.Enabled = false
		return nil, err
	}
	defer lConn.Close()

	if src.BindDN != "" && src.BindPassword != "" {
		err := lConn.Bind(src.BindDN, src.BindPassword)
		if err != nil {
			log.Log.Debugf("Failed to bind as BindDN[%s]: %v", src.BindDN, err)
			return nil, err
		}
		log.Log.Debugf("Bound as BindDN %s", src.BindDN)
	} else {
		log.Log.Debugf("Proceeding with anonymous LDAP search.")
	}

	userFilter := fmt.Sprintf(src.Filter, "*")

	attribs := []string{src.AttributeUsername, src.AttributeName, src.AttributeSurname, src.AttributeMail}

	log.Log.Debugf("Fetching attributes '%v', '%v', '%v', '%v' with filter %s and base %s", src.AttributeUsername, src.AttributeName, src.AttributeSurname, src.AttributeMail, userFilter, src.UserBase)
	search := ldap.NewSearchRequest(
		src.UserBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, userFilter,
		attribs, nil)

	var sr *ldap.SearchResult
	if src.UsePagedSearch() {
		sr, err = lConn.SearchWithPaging(search, src.SearchPageSize)
	} else {
		sr, err = lConn.Search(search)
	}
	if err != nil {
		log.Log.Debugf("LDAP Search failed unexpectedly! (%v)", err)
		return nil, err
	}

	result := make([]*SearchResult, len(sr.Entries))

	for i, v := range sr.Entries {
		result[i] = &SearchResult{
			Username: v.GetAttributeValue(src.AttributeUsername),
			Name:     v.GetAttributeValue(src.AttributeName),
			Surname:  v.GetAttributeValue(src.AttributeSurname),
			Mail:     v.GetAttributeValue(src.AttributeMail),
			IsAdmin:  checkAdmin(lConn, src, v.DN),
		}
		if !result[i].IsAdmin {
			result[i].IsRestricted = checkRestricted(lConn, src, v.DN)
		}
	}

	return result, nil
}
