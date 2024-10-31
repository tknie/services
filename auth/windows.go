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
	"fmt"
	"syscall"
	"unsafe"
)

const LOGON32_LOGON_INTERACTIVE = 2
const LOGON32_PROVIDER_DEFAULT = 0

var (
	advapi     = syscall.NewLazyDLL("advapi32.dll")
	logonUserW = advapi.NewProc("LogonUserW")
)

func validateUser(userName, passwd string) error {
	var handle syscall.Handle
	domain := ""
	r1, r2, lastError := logonUserW.Call(
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(userName))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(domain))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(passwd))),
		LOGON32_LOGON_INTERACTIVE,
		LOGON32_PROVIDER_DEFAULT,
		uintptr(unsafe.Pointer(&handle)),
	)
	fmt.Println(r1, r2, lastError)
	return lastError
}

// callSystemAuthenticate authenticate user and password
func callSystemAuthenticate(serviceName, userName, passwd string) error {
	return validateUser(userName, passwd)
}
