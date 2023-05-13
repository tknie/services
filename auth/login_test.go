package auth

import (
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLoginBasic(t *testing.T) {
	initLog("login.out")
	file, err := os.CreateTemp("/tmp", "test.auth.*.file")
	if err != nil {
		log.Fatal(err)
	}
	os.Remove(file.Name())
	defer os.Remove(file.Name())
	fmt.Println("Realm file:", file.Name())
	as := &Authentication{AuthenticationServer: []*AuthenticationServer{{Type: "file", PasswordFile: file.Name()}}}
	err = InitLoginService(as)
	assert.NoError(t, err)
	nrUsers := CountLoginUser(as.AuthenticationServer[0].PasswordFile)
	assert.Equal(t, 1, nrUsers)
	RemoveLoginService(as)
	nrUsers = CountLoginUser(as.AuthenticationServer[0].PasswordFile)
	assert.Equal(t, -1, nrUsers)

}

func TestLoginWatcher(t *testing.T) {
	initLog("login.out")
	file, err := os.CreateTemp("/tmp", "test.auth.*.file")
	if err != nil {
		log.Fatal(err)
	}
	fileName := file.Name()
	os.Remove(file.Name())
	//defer os.Remove(file.Name())
	fmt.Println("Realm file:", file.Name())
	as := &Authentication{AuthenticationServer: []*AuthenticationServer{{Type: "file", PasswordFile: file.Name()}}}
	err = InitLoginService(as)
	assert.NoError(t, err)
	extraUser := fmt.Sprintf("%s: SHA512:%s, user", "tkn", genPwd())
	fmt.Println("Add extra user:", extraUser)
	err = addRealmFile(t, fileName, extraUser)
	if err != nil {
		return
	}
	time.Sleep(10 * time.Second)

	nrUsers := CountLoginUser(as.AuthenticationServer[0].PasswordFile)
	assert.Equal(t, 2, nrUsers)
	RemoveLoginService(as)
	nrUsers = CountLoginUser(as.AuthenticationServer[0].PasswordFile)
	assert.Equal(t, -1, nrUsers)

}

func addRealmFile(t *testing.T, fileName, data string) error {
	f, err := os.OpenFile(fileName, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if !assert.NoError(t, err) {
		return err
	}
	defer f.Close()

	if _, err = f.WriteString(data); !assert.NoError(t, err) {
		return err
	}
	return nil
}

func genPwd() string {
	pwd := GenerateHash("SHA256", fmt.Sprintf("%010d", time.Now().Unix()))
	return pwd
}
