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

package services

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/tknie/log"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Logging contains log parameters
type Logging struct {
	TraceLocation  string `xml:"directory,attr"`
	ServerLocation string `xml:"serverlog,attr"`
	LogLevel       string `xml:"level,attr"`
	MaxSize        int    `xml:"maxsize,attr"`
	MaxBackups     int    `xml:"maxbackups,attr"`
	MaxAge         int    `xml:"maxage,attr"`
	Compress       bool   `xml:"compress,attr"`
}

// LogLevel defined, 0 - no debug, 1 - debug, 2 - info
var LogLevel = 0

func init() {
	ed := os.Getenv("ENABLE_DEBUG")
	switch ed {
	case "1", "debug":
		LogLevel = 1
	case "2", "info":
		LogLevel = 2
	default:
		LogLevel = 0
	}
	for _, env := range os.Environ() {
		s := strings.Split(env, "=")
		clearEnv(s[0])
	}
}

func clearEnv(envName string) {
	envValue := os.Getenv(envName)
	if envValue != "" {
		if envValue[0] == '"' && envValue[len(envValue)-1] == '"' {
			s := envValue[1 : len(envValue)-1]
			os.Setenv(envName, s)
		}
	}

}

func initServerOutput(xlog *Logging) {
	xlog.InitTraceLogging()
	serverLogName := xlog.ServerLocation
	if serverLogName == "" {
		serverLogName = xlog.TraceLocation
	}
	xlog.ServerLocation = checkOutputFile(serverLogName, "server.log")
	log.Log.Debugf("Init logging to %s", serverLogName)
	xlog.OpenMessageLog()
}

func checkOutputFile(outputFileName, defaultLogFileName string) string {
	serverMsgLocation := strings.Trim(os.ExpandEnv(outputFileName), " ")
	if stat, err := os.Stat(serverMsgLocation); err == nil {
		if stat.IsDir() {
			serverMsgLocation = serverMsgLocation + string(os.PathSeparator) + defaultLogFileName
		}
	} else {
		serverMsgLocation = strings.Trim(serverMsgLocation, " ")
		if strings.HasSuffix(serverMsgLocation, "/") {
			serverMsgLocation = serverMsgLocation + string(os.PathSeparator) + defaultLogFileName
		}
	}
	return serverMsgLocation
}

func newWinFileSink(u *url.URL) (zap.Sink, error) {
	// Remove leading slash left by url.Parse()
	return os.OpenFile(u.Path[1:], os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
}

func checkTraceLevel(logLevel string) zapcore.Level {
	level := zapcore.ErrorLevel
	ed := os.Getenv("ENABLE_DEBUG")
	if ed == "" {
		ed = logLevel
	}
	switch strings.ToLower(ed) {
	case "1", "debug":
		level = zapcore.DebugLevel
		log.SetDebugLevel(true)
	case "2", "info":
		level = zapcore.InfoLevel
	default:
		level = zapcore.ErrorLevel
	}
	return level
}

// InitTraceLogging init trace logging with log level
func (xlog *Logging) InitTraceLogging() {
	switch log.Log.(type) {
	case *zap.SugaredLogger:
		return
	default:
	}
	name := checkOutputFile(xlog.TraceLocation, "trace.log")
	logName := name
	if runtime.GOOS == "windows" {
		zap.RegisterSink("winfile", newWinFileSink)
		//		OutputPaths: []string{"stdout", "winfile:///" + filepath.Join(GlobalConfigDir.Path, "info.log.json")},
		name = "winfile:///" + name
	} else {
		name = "file://" + filepath.ToSlash(name)
	}

	level := checkTraceLevel(xlog.LogLevel)
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
	w := zapcore.AddSync(&lumberjack.Logger{
		Filename:   filepath.ToSlash(logName),
		MaxSize:    xlog.MaxSize, // megabytes
		MaxBackups: xlog.MaxBackups,
		MaxAge:     xlog.MaxAge, // days
		Compress:   xlog.Compress,
	})

	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.TimeKey = "timestamp"
	encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder

	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(encoderCfg),
		w,
		level,
	)
	logger := zap.New(core)
	defer logger.Sync()
	sugar := logger.Sugar()
	log.Log = sugar
	log.Log.Infof("Start tracing of service or application")
	log.Log.Infof("Logging config: %#v", xlog)
	ServerMessage("Trace '" + xlog.LogLevel + "' log send to " + logName)
}
