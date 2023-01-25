package auth

import (
	"database/sql"
	"errors"
	"strings"

	"github.com/tknie/log"
)

type authDatabase struct {
	layer  string
	URL    string
	query  string
	enable bool
}

var listAuthDatabase = make([]*authDatabase, 0)

// RegisterDatabaseForAuth register principal hooks
func RegisterDatabaseForAuth(layer, URL, query string) {
	listAuthDatabase = append(listAuthDatabase, &authDatabase{layer, URL, query, true})
}

// PerDatabase authenticate user and password to database
func PerDatabase(dbName, userName, passwd string) error {
	for _, ad := range listAuthDatabase {
		adaptURL := ad.URL
		if userName != "" {
			adaptURL = strings.Replace(adaptURL, "<user>", userName, -1)
		}
		if passwd != "" {
			adaptURL = strings.Replace(adaptURL, "<password>", passwd, -1)
		}
		if dbName != "" {
			adaptURL = strings.Replace(adaptURL, "<database>", dbName, -1)
		}
		err := ad.check(adaptURL)
		if err == nil {
			return nil
		}
		log.Log.Errorf("Error authenticat to %s -> %v\n", dbName, err)
	}
	return errors.New("password authentication failed for user")
}

// check create short test database connection
func (adb *authDatabase) check(URL string) error {
	db, err := sql.Open(adb.layer, URL)
	if err != nil {
		return err
	}
	defer db.Close()

	_, err = db.Query(adb.query)
	if err != nil {
		return err
	}

	return nil
}