//go:build solaris
// +build solaris

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
	"errors"
)

// callSystemAuthenticate authenticate user and password
func callSystemAuthenticate(serviceName, userName, passwd string) error {
	return errors.New("Not supported")
}
