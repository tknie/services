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
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/tknie/log"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const testRole = "performanceRole"

var globalUserCounter = uint64(0)
var globalTokenCounter = uint64(0)

type testPrincipal struct {
	testUUID string
	token    string
	user     string
	pass     string
}

func (tp *testPrincipal) UUID() string {
	if tp.testUUID != "" {
		return tp.testUUID
	}
	return "TestUUID"
}
func (tp *testPrincipal) Name() string {
	return "TestPrincipal"
}
func (tp *testPrincipal) Remote() string {
	return "RemoteHost"
}
func (tp *testPrincipal) AddRoles(r []string) {
	fmt.Println("Add role", r)
}
func (tp *testPrincipal) SetRemote(r string) {
	fmt.Println("Set remote", r)
}
func (tp *testPrincipal) Roles() []string {
	return []string{"xx", testRole}
}
func (tp *testPrincipal) Session() interface{} {
	return nil
}
func (tp *testPrincipal) SetSession(interface{}) {
}

func newWinFileSink(u *url.URL) (zap.Sink, error) {
	// Remove leading slash left by url.Parse()
	return os.OpenFile(u.Path[1:], os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
}

const maxEntries = 200

var userChannel = make(chan *testPrincipal, maxEntries+1)
var tokenChannel = make(chan *testPrincipal, maxEntries+1)
var wg sync.WaitGroup

func initLog(fileName string) (err error) {
	switch log.Log.(type) {
	case *zap.SugaredLogger:
		return
	default:
	}

	p := os.Getenv("LOGPATH")
	if p == "" {
		p = "."
	}

	var name string
	if runtime.GOOS == "windows" {
		zap.RegisterSink("winfile", newWinFileSink)
		//		OutputPaths: []string{"stdout", "winfile:///" + filepath.Join(GlobalConfigDir.Path, "info.log.json")},
		name = "winfile:///" + p + string(os.PathSeparator) + fileName
	} else {
		name = "file://" + filepath.ToSlash(p+string(os.PathSeparator)+fileName)
	}

	fmt.Println("Logging to file", name)
	level := zapcore.ErrorLevel
	ed := os.Getenv("ENABLE_DEBUG")
	if ed == "1" {
		level = zapcore.DebugLevel
		fmt.Println("Enable debug logging into", name)
		log.SetDebugLevel(true)
	}

	rawJSON := []byte(`{
		"level": "error",
		"encoding": "console",
		"outputPaths": [ "XXX"],
		"errorOutputPaths": ["stderr"],
		"encoderConfig": {
		  "messageKey": "message",
		  "levelKey": "level",
		  "levelEncoder": "lowercase"
		}
	  }`)

	var cfg zap.Config
	if err := json.Unmarshal(rawJSON, &cfg); err != nil {
		panic(err)
	}
	cfg.Level.SetLevel(level)
	cfg.OutputPaths = []string{name}
	logger, err := cfg.Build()
	if err != nil {
		panic(err)
	}
	defer logger.Sync()

	sugar := logger.Sugar()

	sugar.Infof("logger construction succeeded %s", "xx")
	log.Log = sugar

	return
}

func TestJWS(t *testing.T) {
	err := initLog("jwt.log")
	if err != nil {
		fmt.Println("ERROR : ", err)
		return
	}
	wt := &WebToken{PrivateKey: "${CURDIR}/keys/apiKey.prv",
		PublicKey: "${CURDIR}/keys/apiKey.pem", IssuerName: "TESTISSUER"}
	err = wt.InitWebTokenJose2()
	assert.NoError(t, err)
	token, err := wt.GenerateJWToken("*", &testPrincipal{})
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
	log.Log.Infof("Signature JWT: %s", token)
	pi, err := wt.JWTContainsRoles(token, []string{"xx"})
	assert.NoError(t, err)
	if !assert.NotNil(t, pi) {
		return
	}
	assert.Equal(t, "TestPrincipal", pi.Name())
	assert.Equal(t, "RemoteHost", pi.Remote())
	assert.Equal(t, []string([]string{"xx"}), pi.Roles())
	assert.Equal(t, "TestUUID", pi.UUID())
}

func TestJWE(t *testing.T) {
	err := initLog("jwt.log")
	if err != nil {
		fmt.Println("ERROR : ", err)
		return
	}
	wt := &WebToken{PrivateKey: "${CURDIR}/keys/apiKey.prv",
		PublicKey: "${CURDIR}/keys/apiKey.pem", Encrypt: true,
		IssuerName: "TESTISSUER"}
	err = wt.InitWebTokenJose2()
	assert.NoError(t, err)
	token, err := wt.GenerateJWToken("*", &testPrincipal{})
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
	log.Log.Infof("Encrypted JWT: %s", token)
	pi, err := wt.JWTContainsRoles(token, []string{"xx"})
	assert.NoError(t, err)
	if !assert.NotNil(t, pi) {
		return
	}
	assert.Equal(t, "TestPrincipal", pi.Name())
	assert.Equal(t, "RemoteHost", pi.Remote())
	assert.Equal(t, []string([]string{"xx"}), pi.Roles())
	assert.Equal(t, "TestUUID", pi.UUID())
}

func TestJWSWrong(t *testing.T) {
	err := initLog("jwt.log")
	if err != nil {
		fmt.Println("ERROR : ", err)
		return
	}
	wt := &WebToken{PrivateKey: "keys/apiKey.prv",
		PublicKey: "keys/apiKey.pem", IssuerName: "TESTISSUER"}
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.dyt0CoTl4WoVjAHI9Q_CwSKhl6d_9rhM3NrXuJttkao"
	pi, err := wt.JWTContainsRoles(token, []string{"xx"})
	assert.Error(t, err)
	assert.Nil(t, pi)
}

func TestJWTPerformance(t *testing.T) {
	err := initLog("jwt.log")
	if err != nil {
		fmt.Println("ERROR : ", err)
		return
	}
	wt := &WebToken{PrivateKey: "keys/apiKey.prv",
		PublicKey: "keys/apiKey.pem", IssuerName: "TESTISSUER"}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go tokenWorker(t, wt)
	}
	wt.InitWebTokenJose2()
	for i := 1; i < maxEntries; i++ {
		u := uuid.New().String()
		tp := &testPrincipal{testUUID: u}
		num := fmt.Sprintf("%03d", i)
		tp.user = "user" + num
		tp.pass = "pass" + num
		userChannel <- tp
	}

	wg.Wait()

	/* uuidHashStore.Range(func(key, value any) bool {
		fmt.Printf("%s=%#v\n", key, value)
		return true
	})*/
	fmt.Println("User storage: ", globalUserCounter)
	fmt.Println("Token storage:", globalUserCounter)
	fmt.Println("Done")
}

func tokenWorker(t *testing.T, wt *WebToken) {
	countUser := uint64(0)
	countToken := uint64(0)
	for {
		select {
		case tpUser := <-userChannel:
			token, err := wt.GenerateJWToken("*", tpUser)
			assert.NoError(t, err)
			tpUser.token = token
			countUser++
			tokenChannel <- tpUser
		case tpToken := <-tokenChannel:
			assert.NotEmpty(t, tpToken.token)
			tpI, err := wt.JWTContainsRoles(tpToken.token, []string{testRole})
			tp := tpI.(*testPrincipal)
			assert.NoError(t, err)
			assert.Equal(t, tp.token, tpToken.token)
			assert.Equal(t, tp, tpToken)
			countToken++
		case <-time.After(10 * time.Second):
			atomic.AddUint64(&globalUserCounter, countUser)
			atomic.AddUint64(&globalTokenCounter, countToken)
			wg.Done()
			fmt.Println("Proceed: ", countUser, countToken)
			return
		}
	}
}
