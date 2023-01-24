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

package services

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tknie/errorrepo"
	"github.com/tknie/log"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

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

func TestErrors(t *testing.T) {
	err := initLog("errors.log")
	if err != nil {
		fmt.Println("ERROR : ", err)
		return
	}

	assert.Equal(t, "Unknown error ...SYS00001", NewError("SYS00001").Error())
	fmt.Println("Test")
	assert.Equal(t, "SYS00002: user xxx unknown", NewError("SYS00002", "xxx").Error())
	assert.Equal(t, "SYS00003: not implemented", NewError("SYS00003").Error())
	assert.Equal(t, "SYS00004: user totot already in list", NewError("SYS00004", "totot").Error())
	assert.Equal(t, "SYS00005: user totot not found in list", NewError("SYS00005", "totot").Error())
	assert.Equal(t, "SYS00006: given PID file alala is a directory", NewError("SYS00006", "alala").Error())
	assert.Equal(t, "SYS00007: given PID file ffff is already available", NewError("SYS00007", "ffff").Error())
	assert.Equal(t, "SYS00008: check PID file adada fails: sdsds", NewError("SYS00008", "adada", "sdsds").Error())
	assert.Equal(t, "SYS00002: user tom unknown", errorrepo.NewErrorLocale("en", "SYS00002", "tom").Error())
}
