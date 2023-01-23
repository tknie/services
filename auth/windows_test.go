//go:build windows
// +build windows

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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWindowsLogin(t *testing.T) {
	err := SystemAuthenticate("", "adatest@EUR", "XXXXYYYwrongPassword")
	assert.NoError(t, err)
}
