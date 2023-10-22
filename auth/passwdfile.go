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
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/tknie/log"
	"github.com/tknie/services"
)

// CheckDefaultPassword check default password must be changed
const CheckDefaultPassword = "Test123"

const realmHeader = `# Create MD5 hash with
# echo -n "<password>" | md5sum
# on Unix`

type loginEntry struct {
	user     string
	password string
	enc      string
	roles    string
}

// PasswordFileStruct password file struct
type PasswordFileStruct struct {
	realmFile string
	Counter   uint64
	loginMap  sync.Map // map[string]loginEntry
	realmFd   *os.File
	watcher   *fsnotify.Watcher
	done      chan bool
}

// var defaultRealm *PasswordFileStruct
var passwordFileMap = make(map[string]*PasswordFileStruct)

var (
	pmd5    = ""
	psha    = ""
	psha256 = ""
	psha512 = ""
)

func init() {
	pmd5 = GenerateHash("MD5", CheckDefaultPassword)
	psha = GenerateHash("SHA", CheckDefaultPassword)
	psha256 = GenerateHash("SHA256", CheckDefaultPassword)
	psha512 = GenerateHash("SHA512", CheckDefaultPassword)
}

func checkDefaultPassword(user, password string) {
	switch password {
	case pmd5, psha, psha256, psha512:
		services.ServerMessage("WARNING: Default password found for user %s", user)
	default:
	}
}

// CreateDefaultRealm create default realm
func (rfs *PasswordFileStruct) CreateDefaultRealm() (err error) {
	services.ServerMessage("No realm file found, creating autogenerated one")
	rfs.realmFd, err = os.OpenFile(rfs.realmFile, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		return err
	}
	return rfs.createHeader()
}

func (rfs *PasswordFileStruct) createHeader() error {
	header := realmHeader
	if runtime.GOOS == "windows" {
		header = strings.ReplaceAll(header, "\n", services.LineBreak)
	}
	_, err := fmt.Fprintln(rfs.realmFd, header)
	if err != nil {
		return err
	}
	return nil
}

// CreateDefaultUser create default user
func (rfs *PasswordFileStruct) CreateDefaultUser() error {
	newPassword := GenerateHash("MD5", fmt.Sprintf("%d", time.Now().Unix()))
	services.ServerMessage("Please note the following password, it is not logged in any file.")
	services.ServerMessage("Generated admin password -> %s", newPassword)
	psha512 := GenerateHash("SHA512", newPassword)
	fmt.Fprintf(rfs.realmFd, "admin: SHA512:%s, admin"+services.LineBreak, psha512)
	return nil
}

// Close close file descriptor
func (rfs *PasswordFileStruct) Close() {
	if rfs.realmFd != nil {
		rfs.realmFd.Close()
	}
	rfs.realmFd = nil
}

// NewInitFileRealm new init file realm (Create new one if not available)
func NewInitFileRealm(realmFile string, createAutogenerated bool) (*PasswordFileStruct, error) {
	rfs := &PasswordFileStruct{loginMap: sync.Map{}}
	rfs.realmFile = os.ExpandEnv(realmFile)
	log.Log.Debugf("Opening password file %s...(0666)", rfs.realmFile)
	file, err := os.OpenFile(rfs.realmFile, os.O_RDWR, 0666)
	if os.IsNotExist(err) {
		log.Log.Debugf("Password file create default realm")
		err = rfs.CreateDefaultRealm()
		if err != nil {
			services.ServerMessage("Error generating default realm file %s: %v", rfs.realmFile, err)
			return nil, err
		}
		if createAutogenerated {
			err = rfs.CreateDefaultUser()
			if err != nil {
				services.ServerMessage("Error generating default user in realm file %s: %v", rfs.realmFile, err)
				return nil, err
			}
		}
	} else {
		if err != nil {
			services.ServerMessage("Error opening realm file %s: %v", rfs.realmFile, err)
			return nil, err
		}
		rfs.realmFd = file
	}
	log.Log.Debugf("End opening realm file %s", rfs.realmFile)
	return rfs, nil
}

// NewAppendPasswordFile new append password file to append only
func NewAppendPasswordFile(realmFile string) *PasswordFileStruct {
	rfs := &PasswordFileStruct{loginMap: sync.Map{}}
	rfs.realmFile = os.ExpandEnv(realmFile)
	rf, err := os.OpenFile(realmFile, os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		services.ServerMessage("Error opening realm file: %v", err)
		return nil
	}
	rfs.realmFd = rf
	return rfs
}

// InitPasswordFile init password to file data
func InitPasswordFile(passwordFile string) (err error) {
	log.Log.Debugf("Init password file %s", passwordFile)
	var newCr *PasswordFileStruct
	if cr, ok := passwordFileMap[passwordFile]; !ok {
		cr, err = NewInitFileRealm(passwordFile, true)
		if err != nil {
			return
		}
		passwordFileMap[passwordFile] = cr
		newCr = cr
	} else {
		newCr = cr
	}
	if newCr != nil {
		log.Log.Debugf("Load and watch file")
		err = newCr.LoadPasswordFile()
		if err != nil {
			services.ServerMessage("Loading file realm failed: %v", err)
			return
		}
		newCr.realmWatcher()
	}
	log.Log.Debugf("Init password file done")
	return
}

// RemovePasswordFile remove password to file data
func RemovePasswordFile(passwordFile string) {
	if cr, ok := passwordFileMap[passwordFile]; ok {
		cr.endRealmWatcher()
		delete(passwordFileMap, passwordFile)
	}

}

// LoadPasswordFile load user of file realm
func (rfs *PasswordFileStruct) LoadPasswordFile() (err error) {
	if rfs.realmFd == nil {
		return fmt.Errorf("realm file not opened correctly")
	}
	_, err = rfs.realmFd.Seek(0, 0)
	if err != nil {
		return
	}
	return rfs.scan()
}

func (rfs *PasswordFileStruct) scan() (err error) {
	scanner := bufio.NewScanner(rfs.realmFd)
	count := 0
	for scanner.Scan() {
		line := scanner.Text()
		log.Log.Debugf("Scan line: %s", line)
		count += rfs.parseLine(line)
	}

	if err = scanner.Err(); err != nil {
		services.ServerMessage("Error scanning realm file %s after %d read: %v", rfs.realmFile, count, err)
		return
	}
	services.ServerMessage("Found %d user(s) in realm file", rfs.CountLoginUser())
	return
}

// func (rfs *PasswordFileStruct) readFile(lineBreak string) (err error) {
// 	b := make([]byte, 4096)
// 	var buffer bytes.Buffer
// 	var read int
// 	count := 0
// 	lineBuffer := ""
// 	_, err = rfs.realmFd.Seek(0, 0)
// 	if err != nil {
// 		return
// 	}
// 	for err != io.EOF {
// 		read, err = rfs.realmFd.Read(b)
// 		if err == io.EOF {
// 			return nil
// 		}
// 		if err != nil {
// 			services.ServerMessage("Error scanning file %s after %d read: %v", rfs.realmFile, count, err)
// 			return
// 		}
// 		_, err = buffer.Write(b[:read])
// 		if err != nil {
// 			services.ServerMessage("Error writing file %s: %v", rfs.realmFile, err)
// 			return err
// 		}
// 		lineBuffer = lineBuffer + buffer.String()
// 		n := strings.IndexAny(lineBuffer, lineBreak)
// 		if n > 0 {
// 			count += rfs.parseLine(lineBuffer[:n])
// 			lineBuffer = lineBuffer[n:]
// 		}
// 	}
// 	services.ServerMessage("Read %d new entries of file %s", count, rfs.realmFile)
// 	return
// }

// parseLine and return count of new entries parsed
func (rfs *PasswordFileStruct) parseLine(line string) int {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "#") && line != "" {
		// User adapt password
		i := strings.IndexRune(line, ':')
		if i == -1 {
			return 0
		}
		j := strings.IndexRune(line, ',')
		if j == -1 {
			j = len(line)
		}
		u := strings.ToLower(line[:i])
		entry := loginEntry{user: u}
		p := line[i+1 : j]
		p = strings.Trim(p, " ")
		e := strings.Split(p, ":")
		if len(e) == 2 {
			entry.enc = e[0]
			entry.password = e[1]
		} else {
			entry.password = p
		}
		if j < len(line) {
			entry.roles = line[j:]
		}

		count := 0
		if em, ok := rfs.loginMap.Load(entry.user); ok {
			e := em.(*loginEntry)
			if e.enc != entry.enc || e.password != entry.password {
				checkDefaultPassword(entry.user, entry.password)
				rfs.loginMap.Store(entry.user, &entry)
			}
		} else {
			checkDefaultPassword(entry.user, entry.password)
			rfs.loginMap.Store(entry.user, &entry)
			rfs.Counter++
			count++
		}
		log.Log.Debugf("User auth for %s -> %s (%s)", entry.user, entry.password, entry.enc)
		return count
	}
	return 0
}

// realmWatcher initialize realm file watcher checking modifications and
// reload the configuration
func (rfs *PasswordFileStruct) realmWatcher() {
	if rfs == nil {
		return
	}
	var err error
	rfs.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		services.ServerMessage("ERROR creating %s watcher: %v", rfs.realmFile, err)
	}
	rfs.done = make(chan bool)
	go func() {
		for {
			select {
			// watch for events
			case event := <-rfs.watcher.Events:
				services.ServerMessage("Noticed realm file changed in %s (%v)", event.Name, event.Op)
				err = rfs.LoadPasswordFile()
				if err != nil {
					services.ServerMessage("Realm file watcher load ERROR received: %v", err)
				}
			case err := <-rfs.watcher.Errors:
				services.ServerMessage("Realm file watcher ERROR received: %v", err)
			case <-rfs.done:
				rfs.watcher.Close()
				services.ServerMessage("Realm file watcher removed for %s", rfs.realmFile)
				rfs.done <- true
				return
			}
		}
	}()
	// out of the box fsnotify can watch a single file, or a single directory
	if err := rfs.watcher.Add(rfs.realmFile); err != nil {
		services.ServerMessage("ERROR add realm watcher at %s: %v", rfs.realmFile, err)
		return
	}
	services.ServerMessage("Watch changes on realm file %s", rfs.realmFile)
}

// endRealmWatcher end realm file watcher checking modifications
func (rfs *PasswordFileStruct) endRealmWatcher() {
	if rfs == nil || rfs.watcher == nil {
		return
	}
	services.ServerMessage("Trigger end of Realm file watcher %s", rfs.realmFile)
	rfs.done <- true
	<-rfs.done
	//rfs.watcher.Close()
}

// CheckUser check user to realm file
func (rfs *PasswordFileStruct) CheckUser(u string) bool {
	user := strings.ToLower(u)
	_, ok := rfs.loginMap.Load(user)
	return ok
}

// AppendUserToPasswordFile append user to realm file
func (rfs *PasswordFileStruct) AppendUserToPasswordFile(user, newPassword, roles string) error {
	err := rfs.LoadPasswordFile()
	if err != nil {
		return err
	}
	if _, ok := rfs.loginMap.Load(user); ok {
		return fmt.Errorf("user %s already in file", user)
	}
	psha512 := GenerateHash("SHA512", strings.Trim(newPassword, " "))
	_, err = fmt.Fprintf(rfs.realmFd, "%s: SHA512:%s, %s"+services.LineBreak, user, psha512, roles)
	return err
}

// UpdateUserPasswordToRealmFile update user password to realm file
func (rfs *PasswordFileStruct) UpdateUserPasswordToRealmFile(user, newPassword string) error {
	if em, ok := rfs.loginMap.Load(user); ok {
		e := em.(*loginEntry)
		e.password = GenerateHash("SHA512", newPassword)
		e.enc = "SHA512"
		return nil
	}
	return fmt.Errorf("user %s not found in realm file", user)
}

// FlushUserToPasswordFile flush user to realm file
func (rfs *PasswordFileStruct) FlushUserToPasswordFile() error {
	rfs.realmFd.Seek(0, 0)
	err := rfs.createHeader()
	if err != nil {
		return err
	}
	user := make([]string, 0)
	count := uint64(0)
	rfs.loginMap.Range(func(key, value interface{}) bool {
		user = append(user, key.(string))
		count++
		return true
	})
	rfs.Counter = count
	sort.Strings(user)
	for _, u := range user {
		if value, ok := rfs.loginMap.Load(u); ok {
			e := value.(*loginEntry)
			_, err = fmt.Fprintf(rfs.realmFd, "%s: %s:%s, %s"+services.LineBreak, e.user, e.enc, e.password, e.roles)
			if err != nil {
				fmt.Printf("Error flushing realm: %v\n", err)
			}
		}
	}
	return err
}

// // Updater auth updater
// func Updater(authentication *Authentication) {
// 	for {
// 		if authentication != nil {
// 			for _, s := range authentication.AuthenticationServer {
// 				if s.AuthMethod == FileMethod {
// 					if defaultRealm == nil {
// 						defaultRealm = NewInitFileRealm(s.Realm.File, true)
// 					}
// 					if defaultRealm != nil {
// 						err := defaultRealm.LoadPasswordFile()
// 						if err != nil {
// 							fmt.Println("Load file realm data error", err)
// 						}
// 					}
// 				}
// 			}
// 		}
// 		time.Sleep(time.Duration(120) * time.Second)
// 	}
// }

// CheckPasswordFileUser auth user and password for default realm
func CheckPasswordFileUser(u, password string) (string, error) {
	if len(passwordFileMap) == 0 {
		log.Log.Debugf("Init of file realm not done")
		return "", fmt.Errorf("init file realm not done")
	}
	for _, realm := range passwordFileMap {
		roles, err := realm.CheckPasswordFileUser(u, password)
		if err == nil {
			return roles, err
		}
		if err.Error() != "User not found" {
			return roles, err
		}
	}
	return "", errors.New("User not defined")
}

// CheckPasswordFileUser auth user and password for default realm
func (rfs *PasswordFileStruct) CheckPasswordFileUser(u, password string) (string, error) {
	user := strings.ToLower(u)
	if em, ok := rfs.loginMap.Load(user); ok {
		e := em.(*loginEntry)
		s := GenerateHash(e.enc, password)
		log.Log.Debugf("Found user auth for %s -> %s (%s)", e.user, e.password, e.enc)
		log.Log.Debugf("%s ALL: %s != %s", e.enc, s, e.password)
		if e.password == s {
			return e.roles, nil
		}
		log.Log.Debugf("Realm file check fail: password mismatch of user %s", user)
		return "", errors.New("password mismatch")
	}
	log.Log.Debugf("Realm file check fail: user %s not found", user)
	return "", errors.New("User not found")
}

// GenerateHash generate hash by given hash algorithm
func GenerateHash(enc, password string) string {
	switch strings.ToUpper(enc) {
	case "MD5":
		h := md5.New()
		h.Write([]byte(password))
		return fmt.Sprintf("%x", h.Sum(nil))
	case "SHA":
		h := sha1.New()
		h.Write([]byte(password))
		return fmt.Sprintf("%x", h.Sum(nil))
	case "SHA256":
		h := sha256.New()
		h.Write([]byte(password))
		return fmt.Sprintf("%x", h.Sum(nil))
	case "SHA512":
		h := sha512.New()
		h.Write([]byte(password))
		return fmt.Sprintf("%x", h.Sum(nil))
	default:
	}
	return password
}

// CountLoginUser count number of registered login user
func CountLoginUser(passwordFile string) int {
	if rfs, ok := passwordFileMap[passwordFile]; ok {
		return rfs.CountLoginUser()
	}
	return -1
}

// CountLoginUser count number of registered login user for a specific realm file
func (rfs *PasswordFileStruct) CountLoginUser() int {
	counter := 0
	rfs.loginMap.Range(func(key, vaue any) bool {
		counter++
		return true
	})
	return counter
}
