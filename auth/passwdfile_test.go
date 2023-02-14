package auth

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRealmUnix(t *testing.T) {
	err := initLog("realm.log")
	if err != nil {
		fmt.Println("ERROR : ", err)
		return
	}
	realmFile := os.ExpandEnv("${CURDIR}/files/auth.passwords.unix")
	rfs, err := NewInitFileRealm(realmFile, false)
	if !assert.NoError(t, err) {
		return
	}
	if !assert.NotNil(t, rfs) {
		return
	}
	assert.NotNil(t, rfs.realmFd)
	err = rfs.scan()
	if !assert.NoError(t, err) {
		return
	}
	v, ok := rfs.loginMap.Load("admin")
	assert.True(t, ok)
	le := v.(*loginEntry)
	assert.Equal(t, "admin", le.user)
	assert.Equal(t, "SHA512", le.enc)
	assert.Equal(t, ", admin, job", le.roles)
	assert.Equal(t, "c12834f1031f6497214f27d4432f26517ad494156cb88d512bdb1dc4b57db2d692a3dfa269a19b0a0a2a0fd7d6a2a885e33c839c93c206da30a187392847ed27", le.password)
	roles, err := rfs.CheckPasswordFileUser("admin", "Test123")
	assert.Nil(t, err)
	assert.Equal(t, ", admin, job", roles)
	roles, err = rfs.CheckPasswordFileUser("tkn@domain.com", "testpass")
	assert.Nil(t, err)
	assert.Equal(t, ", xxx", roles)
	_, err = rfs.CheckPasswordFileUser("md5user", "test333")
	assert.Error(t, err)
	roles, err = rfs.CheckPasswordFileUser("md5user", "Test123")
	assert.Nil(t, err)
	assert.Equal(t, ", user", roles)
	roles, err = rfs.CheckPasswordFileUser("yyy", "xxx")
	assert.Error(t, err, "xx")
	assert.Equal(t, "", roles)
}

func TestRealmWindows(t *testing.T) {
	err := initLog("realm.log")
	if err != nil {
		fmt.Println("ERROR : ", err)
		return
	}
	realmFile := os.ExpandEnv("${CURDIR}/files/auth.passwords.win")
	rfs, err := NewInitFileRealm(realmFile, false)
	if !assert.NoError(t, err) {
		return
	}
	if !assert.NotNil(t, rfs) {
		return
	}
	assert.NotNil(t, rfs.realmFd)
	err = rfs.scan()
	if !assert.NoError(t, err) {
		return
	}
	v, ok := rfs.loginMap.Load("admin")
	assert.True(t, ok)
	le := v.(*loginEntry)
	assert.Equal(t, "admin", le.user)
	assert.Equal(t, "SHA512", le.enc)
	assert.Equal(t, ", admin, job", le.roles)
	assert.Equal(t, "c12834f1031f6497214f27d4432f26517ad494156cb88d512bdb1dc4b57db2d692a3dfa269a19b0a0a2a0fd7d6a2a885e33c839c93c206da30a187392847ed27", le.password)
	roles, err := rfs.CheckPasswordFileUser("admin", "Test123")
	assert.Nil(t, err)
	assert.Equal(t, ", admin, job", roles)
	roles, err = rfs.CheckPasswordFileUser("admin", "testpass")
	assert.Error(t, err)
	assert.Equal(t, "password mismatch", err.Error())
	assert.Empty(t, roles)
}

func TestRealmVirtual(t *testing.T) {
	os.Remove("/tmp/realm.file.test.restgo")
	rfs, err := NewInitFileRealm("/tmp/realm.file.test.restgo", false)
	if !assert.NoError(t, err) {
		return
	}
	if !assert.NotNil(t, rfs) {
		return
	}
	rfs.AppendUserToPasswordFile("test", "manage123", "sagadmin, aifadmin, jobadmin,fileadmin")
	// 22d16eba32c4cb0ebf725ba4b7e6da35cc6dda9dab12d597d8b8c0ed8fe368d9cef4e6e5cf4b1a8fcab92db90a27f8f9788a2c0138ad3afc4fc83eb4c489e92c
	err = rfs.FlushUserToPasswordFile()
	assert.NoError(t, err)
	err = rfs.scan()
	assert.NoError(t, err)
	v, ok := rfs.loginMap.Load("test")
	assert.True(t, ok)
	le := v.(*loginEntry)
	assert.Equal(t, "test", le.user)
	assert.Equal(t, "SHA512", le.enc)
	assert.Equal(t, ", sagadmin, aifadmin, jobadmin,fileadmin", le.roles)
	assert.Equal(t, "22d16eba32c4cb0ebf725ba4b7e6da35cc6dda9dab12d597d8b8c0ed8fe368d9cef4e6e5cf4b1a8fcab92db90a27f8f9788a2c0138ad3afc4fc83eb4c489e92c", le.password)

}
