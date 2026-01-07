/*
* Copyright 2022-2026 Thorsten A. Knieling
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
	"encoding/xml"
	"os"

	"github.com/tknie/log"
)

func loadXMLConfig(byteValue []byte, config ConfigInterface) error {
	loadedConfig := config.Default()
	err := xml.Unmarshal(byteValue, loadedConfig)
	if err != nil {
		log.Log.Debugf("Unmarshal error: %#v", err)
		return err
	}

	// Only set logging in server mode
	if config.IsServer() {
		l := config.Logging(loadedConfig)
		if l == nil {
			l = &Logging{TraceLocation: "logs/trace.log",
				ServerLocation: "logs/server.log", LogLevel: "info"}
			config.SetLogging(l)
		}
		once.Do(func() {
			initServerOutput(l)
		})
	}
	log.Log.Debugf("Config DATA: " + string(byteValue))
	log.Log.Debugf("Config Interface: %#v", config)
	return config.Loaded(loadedConfig)
}

func storeXMLConfig(xmlFile *os.File, config ConfigInterface) error {
	log.Log.Debugf("Write configuration file: %#v", config)
	xmlFile.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + LineBreak)
	encoder := xml.NewEncoder(xmlFile)
	encoder.Indent("", "  ")
	err := encoder.Encode(config.Current())
	if err != nil {
		log.Log.Errorf("Write file error: %#v", err)
		ServerMessage("Write configuration file error: %v", err)
		return err
	}
	log.Log.Debugf("Done write configuration file")
	return nil
}
