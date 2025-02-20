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
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"

	"github.com/fsnotify/fsnotify"
	"github.com/tknie/log"
	"github.com/tknie/services"
	"gopkg.in/yaml.v3"
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
	// OIDCClientMethod use OIDC client
	OIDCClientMethod
	// CallbackMethod callback method
	CallbackMethod
)

type watchLoader struct {
	file string
	role AccessRole
}

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
	case "oidc":
		return OIDCClientMethod
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
	ClientID     string   `xml:"clientID,omitempty" yaml:"clientID,omitempty"`
	ClientSecret string   `xml:"clientSecret,omitempty" yaml:"clientSecret,omitempty"`
	URL          string   `xml:"url,omitempty" yaml:"url,omitempty"`
	RedirectURL  string   `xml:"redirectUrl,omitempty" yaml:"redirectUrl,omitempty"`
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
	ReadMap  map[string]bool `xml:"-" yaml:"-" json:"-"`
	WriteMap map[string]bool `xml:"-" yaml:"-" json:"-"`
}

// Users REST user list allowed accessing data
type Users struct {
	Role    AccessRole       `xml:"-" yaml:"-" json:"-"`
	File    string           `xml:"-" yaml:"-" json:"-"`
	Default *Default         `xml:"Default" yaml:"default,omitempty"`
	User    []*User          `xml:"User"  yaml:"user,omitempty"`
	UserMap map[string]*User `xml:"-" yaml:"-" json:"-"`
}

var roleNames = []string{"Administrator", "User"}

// PermissionPrefix permission group prefix used for different groups
// and prefix characters
var PermissionPrefix = []string{"#", "^", ">"}

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
					services.ServerMessage("Error loading admin user: %v", err)
				} else {
					AllowedAdministrators = u
				}
			case userEvent := <-userWatcher.Events:
				u, err := loadUser(userEvent.Name)
				if err != nil {
					services.ServerMessage("Error loading users: %v", err)
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
	return ValidUser(AdministratorRole, true, &UserInfo{User: user}, "")
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
	log.Log.Debugf("Validate user role: %s for resource %s (write=%v)", user, resource, writeAccess)
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
				log.Log.Debugf("User write check user=%s read=%s write=%s resource=%s w=%v", user, us.Read, us.Write, resource, writeAccess)
				return checkMapFits(user, resource, us.WriteMap)
			}
			log.Log.Debugf("User read check user=%s read=%s write=%s resource=%s", user, us.Read, us.Write, resource)
			return checkMapFits(user, resource, us.ReadMap)
		}
		log.Log.Debugf("Allowed user map return %v", us)
	} else {
		log.Log.Debugf("Check default permissions")
		if writeAccess {
			return checkMapFits(user, resource, AllowedUsers.Default.WriteMap)
		}
		if AllowedUsers.Default == nil {
			return false
		}
		log.Log.Debugf("Default check read=%s write=%s resource=%s", AllowedUsers.Default.Read, AllowedUsers.Default.Write, resource)
		return checkMapFits(user, resource, AllowedUsers.Default.ReadMap)

	}
	log.Log.Debugf("No user map validation %#v", AllowedUsers.UserMap)
	return false
}

func checkMapFits(user, resource string, checkMap map[string]bool) bool {
	log.Log.Debugf("Check user %s in resource %s of %v", user, resource, checkMap)
	if x, ok := checkMap[resource]; ok {
		log.Log.Debugf("User map resource %s=%v return=%v", resource, checkMap[resource], x)
		return x
	}

	for _, p := range PermissionPrefix {
		if strings.HasPrefix(resource, p) {
			if x, ok := checkMap[p+"*"]; ok {
				log.Log.Debugf("All user set for prefix " + p)
				return x
			}
			return false
		}
	}
	if x, ok := checkMap["*"]; ok {
		log.Log.Debugf("All read user set")
		return x
	}
	log.Log.Debugf("Not found read map set")
	return false
}

// ValidUser check the role of the user
func ValidUser(role AccessRole, writeAccess bool, user *UserInfo, resource string) bool {
	if user != nil {
		switch role {
		case AdministratorRole:
			return checkAdminstratorRole(user.User)
		case UserRole:
			return checkUserRole(user.User, resource, writeAccess)
		default:
			log.Log.Debugf("Role invalid")
		}
	}
	return false
}

func evaluateRoles(principal PrincipalInterface) {
	principal.AddRoles([]string{"user"})
	if ValidUser(AdministratorRole, true, &UserInfo{User: principal.Name()}, "") {
		principal.AddRoles([]string{"admin"})
	}
}

func loadUser(file string) (*Users, error) {
	fileEnvResolved := os.ExpandEnv(file)

	ext := strings.ToLower(filepath.Ext(file))

	data, err := services.ReadConfig(fileEnvResolved)
	if err != nil {
		log.Log.Debugf("Error opening role list: %v", err)
		services.ServerMessage("Warning: Error reading config %s: %v", file, err)
		return nil, err
	}

	u := &Users{File: file, UserMap: make(map[string]*User)}
	switch ext {
	case ".xml":
		err = xml.Unmarshal(data, u)
		if err != nil {
			log.Log.Debugf("Unmarshal error: %#v", err)
			services.ServerMessage("Warning: error parsing %s list: %v", file, err)
			return nil, err
		}
	case ".json":
		err = json.Unmarshal(data, u)
		if err != nil {
			log.Log.Debugf("Unmarshal error: %#v", err)
			services.ServerMessage("Warning: error parsing %s list: %v", file, err)
			return nil, err
		}
	case ".yaml":
		err = yaml.Unmarshal(data, u)
		if err != nil {
			log.Log.Debugf("Unmarshal error: %#v", err)
			services.ServerMessage("Warning: error parsing %s list: %v", file, err)
			return nil, err
		}
	default:
		err = xml.Unmarshal(data, u)
		if err != nil {
			log.Log.Debugf("Unmarshal error: %#v", err)
			services.ServerMessage("Warning: error parsing %s list: %v", file, err)
			return nil, err
		}
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
		log.Log.Debugf("User map %v", u.UserMap)
	}
	return u, nil
}

// LoadUsers load permission rights
func LoadUsers(role AccessRole, file string, watcher bool) error {
	if file == "" {
		services.ServerMessage("Warning: %s access list not defined", role.name())
		return nil
	}
	watchHandler := &watchLoader{file: file, role: role}
	if watcher {
		services.InitWatcher(file, watchHandler, loadUserWatcher)
	}
	return loadUserWatcher("init", watchHandler)
}

func loadUserWatcher(event string, handler any) error {
	config := handler.(*watchLoader)
	u, err := loadUser(config.file)
	if err != nil {
		return err
	}
	if config.role == AdministratorRole {
		AllowedAdministrators = u
		f := os.ExpandEnv(config.file)
		if err := adminWatcher.Add(f); err != nil {
			services.ServerMessage("ERROR add admin watcher %s: %v", config.file, err)
		}
	} else {
		AllowedUsers = u
		f := os.ExpandEnv(config.file)
		if err := userWatcher.Add(f); err != nil {
			services.ServerMessage("ERROR add user watcher %s: %v", config.file, err)
		}
	}

	return nil
}

// ClearUsers clear permission rights
func ClearUsers() {
	AllowedAdministrators = nil
	AllowedUsers = nil
}
