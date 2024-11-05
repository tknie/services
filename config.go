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
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/tknie/log"
)

// BuildDate build date
var BuildDate string

// BuildVersion build version
var BuildVersion string

// Version component version
var Version string

var watcher *fsnotify.Watcher
var done chan bool

var once sync.Once

var configLock sync.Mutex

// ConfigStoreType config store type
type ConfigStoreType byte

const (
	// NoStoreType no store type found
	NoStoreType ConfigStoreType = iota
	// XMLStoreType using XML to store config
	XMLStoreType
	// YAMLStoreType using YAML to store config
	YAMLStoreType
	// JSONStoreType using JSON to store config
	JSONStoreType
)

// DefaultEnvironment default environment path
var DefaultEnvironment = ""

// ActualConfigStoreType actual config store type
var ActualConfigStoreType = XMLStoreType
var storeTypeSuffixes = []string{".xml", ".yaml", ".json"}

func evaluateConfigStore(file string) ConfigStoreType {
	if file != "" {
		for i, s := range storeTypeSuffixes {
			if strings.HasSuffix(strings.ToLower(file), s) {
				return ConfigStoreType(i + 1)
			}
		}
	}
	return NoStoreType
}

// ConfigInterface config interface for logging
type ConfigInterface interface {
	Logging(interface{}) *Logging
	SetLogging(*Logging)
	Default() interface{}
	Current() interface{}
	Loaded(interface{}) error
	IsServer() bool
}

func loadConfig(file string, config ConfigInterface) error {
	configLock.Lock()
	defer configLock.Unlock()
	log.Log.Debugf("Load config file: %s", file)
	byteValue, err := ReadConfig(file)
	if err != nil {
		return err
	}
	switch ActualConfigStoreType {
	case XMLStoreType:
		return loadXMLConfig(byteValue, config)
	case YAMLStoreType:
		return loadYAMLConfig(byteValue, config)
	case JSONStoreType:
		return loadJSONConfig(byteValue, config)
	default:
	}
	return nil
}

// ParseConfig parse config input with config store type
func ParseConfig(byteValue []byte, config ConfigInterface) error {
	configLock.Lock()
	defer configLock.Unlock()

	switch ActualConfigStoreType {
	case XMLStoreType:
		return loadXMLConfig(byteValue, config)
	case YAMLStoreType:
		return loadYAMLConfig(byteValue, config)
	case JSONStoreType:
		return loadJSONConfig(byteValue, config)
	default:
	}
	return nil
}

// ReadConfig read config file
func ReadConfig(file string) ([]byte, error) {
	xmlFile, err := os.Open(file)
	if err != nil {
		log.Log.Debugf("Open file error: %#v", err)
		return nil, fmt.Errorf("open file err of %s: %v", file, err)
	}
	defer xmlFile.Close()

	fi, _ := xmlFile.Stat()
	log.Log.Debugf("File size=%d", fi.Size())
	var buffer bytes.Buffer
	_, err = io.Copy(&buffer, xmlFile)
	if err != nil {
		log.Log.Debugf("Read file error: %#v", err)
		return nil, fmt.Errorf("read file err of %s: %v", file, err)
	}
	return buffer.Bytes(), nil
}

// initWatcher initialize configuration file watcher checking modifications and
// reload the configuration
func initWatcher(fileName string, config ConfigInterface) (err error) {
	watcher, err = fsnotify.NewWatcher()
	if err != nil {
		ServerMessage("ERROR creating watcher", err)
	}
	done = make(chan bool)
	go func() {
		for {
			select {
			// watch for events
			case event := <-watcher.Events:
				ServerMessage("Noticed configuration changed in %s (%v)", event.Name, event.Op)
				saveConfig := config
				err := loadConfig(event.Name, config)
				if err != nil {
					ServerMessage("Error re-loading configuration: %v", err)
					// Wait for some seconds to retry it
					time.Sleep(5 * time.Second)
					if err := watcher.Add(fileName); err != nil {
						log.Log.Infof("ERROR add watcher %s: %v", fileName, err)
						return
					}
					err := loadConfig(event.Name, config)
					if err != nil {
						config = saveConfig
					}
				}
				// watch for errors
			case err := <-watcher.Errors:
				ServerMessage("Watcher ERROR received: %v", err)
			case <-done:
				watcher.Close()
				return
			}
		}
	}()
	// out of the box fsnotify can watch a single file, or a single directory
	if err := watcher.Add(fileName); err != nil {
		log.Log.Infof("ERROR add watcher %s: %v", fileName, err)
	} else {
		ServerMessage("Watcher enabled for %s", fileName)
	}
	return nil
}

// CloseConfig close configuration watcher and file descriptors
func CloseConfig() {
	done <- true
}

// StoreConfig store configuration
func StoreConfig(file string, config ConfigInterface) error {
	if config == nil {
		return fmt.Errorf("config is not defined")
	}
	if file == "" {
		return fmt.Errorf("file name not set")
	}
	ActualConfigStoreType = evaluateConfigStore(file)
	configFile, err := os.OpenFile(file, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0666)
	// if we os.Open returns an error then handle it
	if err != nil {
		d := time.Now().Format("-20060102-150405")
		err = os.Rename(file, file+d)
		if err != nil {
			ServerMessage("Error renaming storage file %s: %v", file, err)
			log.Log.Debugf("Rename file error: %#v", err)
			return err
		}
		configFile, err = os.OpenFile(file, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0666)
		// if we os.Open returns an error then handle it
		if err != nil {
			ServerMessage("Error opening storage file %s: %v", file, err)
			log.Log.Debugf("Open file error: %#v", err)
			return err
		}
	}
	defer configFile.Close()

	log.Log.Debugf("Write configuration file: %s", file)
	switch ActualConfigStoreType {
	case XMLStoreType:
		return storeXMLConfig(configFile, config)
	case YAMLStoreType:
		return storeYAMLConfig(configFile, config)
	case JSONStoreType:
		return storeJSONConfig(configFile, config)
	default:
	}
	return fmt.Errorf("no store type found")
}

// LoadConfig load old XML configuration
func LoadConfig(file string, config ConfigInterface, watch bool) error {
	ActualConfigStoreType = evaluateConfigStore(file)

	if watch {
		initWatcher(file, config)
	}
	err := loadConfig(file, config)
	if err != nil {
		err = fmt.Errorf("Config read error: " + err.Error())
		return err
	}
	return nil
}
