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
	"os"

	"github.com/tknie/log"
	"gopkg.in/yaml.v3"
)

func loadYAMLConfig(byteValue []byte, config ConfigInterface) error {
	loadedConfig := config.Default()
	err := yaml.Unmarshal(byteValue, loadedConfig)
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

func storeYAMLConfig(xmlFile *os.File, config ConfigInterface) error {
	log.Log.Debugf("Write configuration file: %#v", config)
	xmlFile.WriteString(`# Configureation file` + LineBreak)
	encoder := yaml.NewEncoder(xmlFile)
	encoder.SetIndent(2)

	err := encoder.Encode(config.Current())
	if err != nil {
		log.Log.Errorf("Write file error: %#v", err)
		ServerMessage("Write configuration file error: %v", err)
		return err
	}
	log.Log.Debugf("Done write configuration file")
	return nil
}
