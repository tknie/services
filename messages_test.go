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
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMessages(t *testing.T) {
	denv := os.Getenv("ADADATADIR")
	assert.NotEqual(t, "ABCxyz", denv)
	os.Setenv("ADADATADIR", "ABCxyz")
	e := os.ExpandEnv("${ADADATADIR}")
	assert.Equal(t, "ABCxyz", e)
	e = os.ExpandEnv("rrr${ADADATADIR}yyy")
	assert.Equal(t, "rrrABCxyzyyy", e)
	os.Setenv("CURDIR", "CCCCCC")
	e = os.ExpandEnv("${CURDIR}")
	assert.Equal(t, "CCCCCC", e)
	e = os.ExpandEnv("abc${CURDIR}def")
	assert.Equal(t, "abcCCCCCCdef", e)
	e = os.ExpandEnv("abc${CURDIR}def${ADADATADIR}aa")
	assert.Equal(t, "abcCCCCCCdefABCxyzaa", e)
}

func TestLogMessages(t *testing.T) {
	os.Remove(os.ExpandEnv("${LOGPATH}/x"))
	os.Remove(os.ExpandEnv("${LOGPATH}/x.1"))
	os.Remove(os.ExpandEnv("${LOGPATH}/x.2"))
	os.Remove(os.ExpandEnv("${LOGPATH}/x.3"))
	logging := new(Logging)
	logging.ServerLocation = "${LOGPATH}/x"
	logging.OpenMessageLog()
	ServerMessage("ABC")
	CloseMessageLog()
	logging.ServerLocation = "${LOGPATH}/x"
	logging.OpenMessageLog()
	ServerMessage("XYZ")
	ServerMessage("ZZZ")
	assert.FileExists(t, os.ExpandEnv("${LOGPATH}/x"))
	assert.FileExists(t, os.ExpandEnv("${LOGPATH}/x.1"))
	assert.NoFileExists(t, os.ExpandEnv("${LOGPATH}/x.2"))
}
