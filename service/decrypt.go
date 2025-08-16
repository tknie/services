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

package service

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"strings"

	"github.com/tknie/log"
)

// DecryptPassword decrypt installation password
func DecryptPassword(data, key string) (string, error) {
	log.Log.Debugf("Decrypt password with data='%s' key='%s'", data, key)
	decodedData, err := base64.RawStdEncoding.DecodeString(strings.Trim(data, " "))
	if err != nil {
		log.Log.Debugf("Decode data error: %v", err)
		return "", err
	}
	decodedKey, err := base64.RawStdEncoding.DecodeString(strings.Trim(key, " "))
	if err != nil {
		log.Log.Debugf("Decode key error: %v", err)
		return "", err
	}
	return decryptData(decodedData, decodedKey)
}

// decryptData decrypt password and return plain password
func decryptData(data, key []byte) (string, error) {
	cphr, err := aes.NewCipher(key)
	if err != nil {
		log.Log.Debugf("Cipher key error: %v", err)
		return "", err
	}
	gcm, err := cipher.NewGCM(cphr)
	if err != nil {
		return "", err
	}

	// extract random nonce we added to the beginning of the file
	nonce := data[:gcm.NonceSize()]
	encrypted := data[gcm.NonceSize():]

	x, err := gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return "", err
	}
	log.Log.Debugf("Got password: %c", x[0])
	return string(x), nil
}
