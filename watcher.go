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
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/tknie/log"
)

// ConfigFileWatcher config file watcher configuration
type ConfigFileWatcher struct {
	watcher *fsnotify.Watcher
	done    chan bool
}

// InitWatcher initialize configuration file watcher checking modifications and
// reload the configuration
func InitWatcher(fileName string, handler any, load func(string, any) error) (w *ConfigFileWatcher, err error) {
	w = &ConfigFileWatcher{}
	w.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		ServerMessage("ERROR creating watcher", err)
	}
	w.done = make(chan bool)
	go func() {
		for {
			select {
			// watch for events
			case event := <-w.watcher.Events:
				ServerMessage("Noticed configuration changed in %s (%v)", event.Name, event.Op)
				err := load(event.Name, handler)
				if err != nil {
					ServerMessage("Error re-loading configuration: %v", err)
					// Wait for some seconds to retry it
					time.Sleep(5 * time.Second)
					if err := w.watcher.Add(fileName); err != nil {
						log.Log.Infof("ERROR add watcher %s: %v", fileName, err)
						return
					}
					err := load(event.Name, handler)
					if err != nil {
						log.Log.Errorf("Reload by watcher failed: %v", err)
					}
				}
				// watch for errors
			case err := <-w.watcher.Errors:
				ServerMessage("Watcher ERROR received: %v", err)
			case <-w.done:
				w.watcher.Close()
				return
			}
		}
	}()
	// out of the box fsnotify can watch a single file, or a single directory
	if err := w.watcher.Add(fileName); err != nil {
		log.Log.Infof("ERROR add watcher %s: %v", fileName, err)
	} else {
		ServerMessage("Watcher enabled for %s", fileName)
	}
	return w, nil
}

// CloseConfig close configuration watcher and file descriptors
func (w *ConfigFileWatcher) CloseConfig() {
	w.done <- true
}
