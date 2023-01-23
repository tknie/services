//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris
// +build aix darwin dragonfly freebsd linux netbsd openbsd solaris

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
	"syscall"
)

// LineBreak line break for unix
const LineBreak = "\n"

var handleSignal = []os.Signal{syscall.SIGHUP, syscall.SIGQUIT,
	syscall.SIGTERM, syscall.SIGSTOP}
