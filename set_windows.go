//go:build windows
// +build windows

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
	"os"
)

// LineBreak line break for windows
const LineBreak = "\r\n"

var handleSignal = []os.Signal{os.Interrupt, os.Kill}
