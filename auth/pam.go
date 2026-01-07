//go:build cgo && !solaris && !windows
// +build cgo,!solaris,!windows

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

package auth

import (
	"errors"

	"github.com/tknie/log"
	"github.com/tknie/pam"
)

// callSystemAuthenticate authenticate user and password
func callSystemAuthenticate(pamName, userName, passwd string) error {
	log.Log.Debugf("Call PAM service=" + pamName)
	t, err := pam.StartFunc(pamName, userName, func(s pam.Style, msg string) (string, error) {
		switch s {
		case pam.PromptEchoOff:
			return passwd, nil
		case pam.PromptEchoOn, pam.ErrorMsg, pam.TextInfo:
			return "", nil
		}
		log.Log.Debugf("Unrecognized PAM message style: %d", s)
		return "", errors.New("unrecognized PAM message style")
	})

	if err != nil {
		log.Log.Debugf("Call PAM function error: %v", err)
		return err
	}

	log.Log.Debugf("Call PAM Authenticate")
	if err = t.Authenticate(0); err != nil {
		log.Log.Debugf("Call PAM error: %v", err)
		return err
	}

	log.Log.Debugf("Success PAM Authenticate")
	return nil
}
