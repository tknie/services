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
	"encoding/xml"
	"fmt"
	"os"
	"strings"

	"github.com/fsnotify/fsnotify"
	"github.com/tknie/log"
	"github.com/tknie/services"
)

// AccessRole access role
type AccessRole int

const (
	// AdministratorRole use of administration user
	AdministratorRole AccessRole = iota

	// UserRole user access role
	UserRole
)

// Method method of authenticate
type Method int

const (
	// UnknownMethod unknown
	UnknownMethod Method = iota
	// SystemMethod System method
	SystemMethod
	// FileMethod password file method
	FileMethod
	// LDAPMethod LDAP method
	LDAPMethod
	// OpenIDMethod OpenID method
	OpenIDMethod
	// SQLDatabaseMethod database method
	SQLDatabaseMethod
	// PluginMethod plugin method
	PluginMethod
	// CallbackMethod callback method
	CallbackMethod
)

// MethodType parse method type out of string
func MethodType(s string) Method {
	t := strings.ToLower(strings.TrimSpace(s))
	switch t {
	case "file":
		return FileMethod
	case "system", "pam":
		return SystemMethod
	case "openid":
		return OpenIDMethod
	case "sql":
		return SQLDatabaseMethod
	case "ldap":
		return LDAPMethod
	case "plugin":
		return PluginMethod
	case "callback":
		return CallbackMethod
	}
	return UnknownMethod
}

// Authentication authenticator base
type Authentication struct {
	AuthenticationServer []*AuthenticationServer
}

// AuthenticationServer authentication server
type AuthenticationServer struct {
	Comment      string   `xml:",comment" yaml:"-"`
	Module       string   `xml:"module,attr" yaml:"module,omitempty"`
	Type         string   `xml:"type,attr" yaml:"type,omitempty"`
	Layer        string   `xml:"driver,attr" yaml:"driver,omitempty"`
	AuthMethod   Method   `xml:"-" yaml:"-"`
	Target       string   `xml:"target,omitempty" yaml:"target,omitempty"`
	PasswordFile string   `xml:"passwordFile,omitempty" yaml:"passwordFile,omitempty"`
	LDAP         []Source `xml:"LDAP,omitempty" yaml:"LDAP,omitempty"`
}

// User REST user
type User struct {
	Name     string          `xml:"name,attr" yaml:"name"`
	Read     string          `xml:"read,attr" yaml:"read"`
	Write    string          `xml:"write,attr" yaml:"write"`
	ReadMap  map[string]bool `xml:"-" yaml:"-"`
	WriteMap map[string]bool `xml:"-" yaml:"-"`
}

// Default default rights
type Default struct {
	Read     string          `xml:"read,attr"  yaml:"read"`
	Write    string          `xml:"write,attr" yaml:"write"`
	ReadMap  map[string]bool `xml:"-" yaml:"-"`
	WriteMap map[string]bool `xml:"-" yaml:"-"`
}

// Users REST user list allowed accessing data
type Users struct {
	Role    AccessRole       `xml:"-" yaml:"-"`
	File    string           `xml:"-" yaml:"-"`
	Default *Default         `xml:"Default" yaml:"default,omitempty"`
	User    []*User          `xml:"User"  yaml:"user,omitempty"`
	UserMap map[string]*User `xml:"-" yaml:"-"`
}

var roleNames = []string{"Administrator", "User"}

var userWatcher *fsnotify.Watcher
var adminWatcher *fsnotify.Watcher
var done chan bool

func init() {
	var err error
	userWatcher, err = fsnotify.NewWatcher()
	if err != nil {
		services.ServerMessage("ERROR creating user watcher", err)
	}
	adminWatcher, err = fsnotify.NewWatcher()
	if err != nil {
		services.ServerMessage("ERROR creating admin watcher", err)
	}
	done = make(chan bool)
	go func() {
		for {
			select {
			// watch for events
			case adminEvent := <-adminWatcher.Events:
				u, err := loadUser(adminEvent.Name)
				if err != nil {
					fmt.Println("Error loading admin user:", err)
				} else {
					AllowedAdministrators = u
				}
			case userEvent := <-userWatcher.Events:
				u, err := loadUser(userEvent.Name)
				if err != nil {
					fmt.Println("Error loading admin user:", err)
				} else {
					AllowedUsers = u
				}
			case err := <-adminWatcher.Errors:
				services.ServerMessage("Watcher ERROR received: %v", err)
			case err := <-userWatcher.Errors:
				services.ServerMessage("Watcher ERROR received: %v", err)
			case <-done:
				adminWatcher.Close()
				userWatcher.Close()
				return
			}
		}
	}()
}

func (role AccessRole) name() string {
	return roleNames[role]
}

// AllowedUsers allowed user reading data
var AllowedUsers *Users = nil

// AllowedAdministrators allowed user reading data
var AllowedAdministrators *Users = nil

func generatePermisionMap(p string, d map[string]bool) map[string]bool {
	m := make(map[string]bool)
	if p == "" {
		return d
	}
	for _, t := range strings.Split(p, ",") {
		f := strings.Trim(t, " ")
		if f[0] == '!' {
			m[f[1:]] = false
		} else {
			m[f] = true
		}
	}
	return m
}

// InitPermission init permission
func (user *User) InitPermission(d *Default) {
	user.ReadMap = generatePermisionMap(user.Read, d.ReadMap)
	user.WriteMap = generatePermisionMap(user.Write, d.WriteMap)
}

// Add user to list
func (users *Users) Add(user string) error {
	for _, u := range users.User {
		if u.Name == user {
			return services.NewError("SYS00004", user)
		}
	}
	users.User = append(users.User, &User{Name: user})
	return nil
}

// Delete user from list
func (users *Users) Delete(user string) error {
	for i, u := range users.User {
		if u.Name == user {
			users.User = users.User[:i+copy(users.User[i:], users.User[i+1:])]
			return nil
		}
	}

	return services.NewError("SYS00005", user)
}

// ValidAdmin check the role of the user
func ValidAdmin(user string) bool {
	log.Log.Debugf("Validate admin: %s", user)
	return ValidUser(AdministratorRole, true, user, "")
}

func checkAdminstratorRole(user string) bool {
	log.Log.Debugf("Validate admin role: %s", user)
	if AllowedAdministrators == nil {
		log.Log.Debugf("No administrator set defined, valid...")
		return true
	}
	if us, ok := AllowedAdministrators.UserMap[user]; ok && us != nil {
		log.Log.Debugf("Admin found and granted: %s", user)
		return true
	}
	log.Log.Debugf("Admin denied: %s", user)
	for x, a := range AllowedAdministrators.UserMap {
		log.Log.Debugf("%v=%v", x, a)
	}

	log.Log.Debugf("No administration map validation %#v", AllowedAdministrators.UserMap)
	return false
}

// checkUserRole check the user role access permissions for
// the given user. Dependent to the resource and write or read access
// the configuration is checked.
func checkUserRole(user, resource string, writeAccess bool) bool {
	log.Log.Debugf("Validate user role: %s", user)
	if AllowedUsers == nil {
		log.Log.Debugf("No user set defined/enabled, valid user ...")
		return true
	}
	if resource == "" || user == "" {
		log.Log.Debugf("User/Resource not given")
		return false
	}
	if us, ok := AllowedUsers.UserMap[user]; ok {
		if us != nil {
			log.Log.Debugf("User map defined for %s", user)
			if writeAccess {
				log.Log.Debugf("User check user=%s read=%s write=%s resource=%s w=%v", user, us.Read, us.Write, resource, writeAccess)
				if x, ok := us.WriteMap[resource]; ok {
					log.Log.Debugf("Resource write set to %v", x)
					return x
				}
				if x, ok := us.WriteMap["*"]; ok {
					log.Log.Debugf("All user write set")
					return x
				}
				log.Log.Debugf("Not found write map set")
			} else {
				log.Log.Debugf("User check user=%s read=%s write=%s resource=%s", user, us.Read, us.Write, resource)
				if x, ok := us.ReadMap[resource]; ok {
					log.Log.Debugf("User map resource %s=%v", resource, us.ReadMap[resource])
					return x
				}
				if x, ok := us.ReadMap["*"]; ok {
					log.Log.Debugf("All read user set")
					return x
				}
				log.Log.Debugf("Not found read map set")
			}
		}
	} else {
		log.Log.Debugf("Check default permissions")
		if writeAccess {
			if x, ok := AllowedUsers.Default.WriteMap[resource]; ok {
				log.Log.Debugf("Map write user set (default) %v", x)
				return x
			}
			if x, ok := AllowedUsers.Default.WriteMap["*"]; ok {
				log.Log.Debugf("All write user set (default) for maps %v", ok)
				return x
			}
		} else {
			if AllowedUsers.Default == nil {
				return false
			}
			log.Log.Debugf("Default check read=%s write=%s resource=%s", AllowedUsers.Default.Read, AllowedUsers.Default.Write, resource)
			if x, ok := AllowedUsers.Default.ReadMap[resource]; ok {
				log.Log.Debugf("Resource read user set (default) %v", x)
				return x
			}
			if x, ok := AllowedUsers.Default.ReadMap["*"]; ok {
				log.Log.Debugf("All read user set (default) %v", x)
				return x
			}
		}
	}
	log.Log.Debugf("No user map validation %#v", AllowedUsers.UserMap)
	return false
}

// ValidUser check the role of the user
func ValidUser(role AccessRole, writeAccess bool, user, resource string) bool {
	switch role {
	case AdministratorRole:
		return checkAdminstratorRole(user)
	case UserRole:
		return checkUserRole(user, resource, writeAccess)
	default:
		log.Log.Debugf("Role invalid")
	}
	return false
}

func evaluateRoles(principal PrincipalInterface) {
	principal.AddRoles([]string{"user"})
	if ValidUser(AdministratorRole, true, principal.Name(), "") {
		principal.AddRoles([]string{"admin"})
	}
}

func loadUser(file string) (*Users, error) {
	fileEnvResolved := os.ExpandEnv(file)
	data, err := services.ReadConfig(fileEnvResolved)
	if err != nil {
		log.Log.Debugf("Error opening role list: %v", err)
		services.ServerMessage("Warning: Error reading config %s: %v", file, err)
		return nil, err
	}
	u := &Users{File: file, UserMap: make(map[string]*User)}
	err = xml.Unmarshal(data, u)
	if err != nil {
		log.Log.Debugf("Unmarshal error: %#v", err)
		services.ServerMessage("Warning: error parsing %s list: %v", file, err)
		return nil, err
	}
	if u.Default != nil {
		u.Default.ReadMap = generatePermisionMap(u.Default.Read, nil)
		u.Default.WriteMap = generatePermisionMap(u.Default.Write, nil)

		for _, us := range u.User {
			u.UserMap[us.Name] = us
			us.InitPermission(u.Default)
		}
	} else {
		for _, us := range u.User {
			u.UserMap[us.Name] = us
		}
	}
	return u, nil
}

// LoadUsers load permission rights
func LoadUsers(role AccessRole, file string) error {
	if file == "" {
		services.ServerMessage("Warning: %s access list not defined", role.name())
		return nil
	}
	u, err := loadUser(file)
	if err != nil {
		return err
	}
	if role == AdministratorRole {
		AllowedAdministrators = u
		f := os.ExpandEnv(file)
		if err := adminWatcher.Add(f); err != nil {
			services.ServerMessage("ERROR add admin watcher %s: %v", file, err)
		}
	} else {
		AllowedUsers = u
		f := os.ExpandEnv(file)
		if err := userWatcher.Add(f); err != nil {
			services.ServerMessage("ERROR add user watcher %s: %v", file, err)
		}
	}

	return nil
}
