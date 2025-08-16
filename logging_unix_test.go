//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris
// +build aix darwin dragonfly freebsd linux netbsd openbsd solaris

/*
* Copyright 2022-2025 Thorsten A. Knieling
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
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoggingPlatform(t *testing.T) {
	path := `"abc//xxxx/../xxx"`
	assert.Equal(t, `"abc/xxx"`, filepath.Clean(path))
	fmt.Println("LOGPATH origin:", os.Getenv("LOGPATH"))
	logging := new(Logging)
	logging.ServerLocation = "${LOGPATH}/x"
	logging.TraceLocation = "${LOGPATH}"
	logging.InitTraceLogging()
	fmt.Println("PATH", filepath.Clean(path))
	fmt.Println("Trace:", logging.TraceLocation)
}
