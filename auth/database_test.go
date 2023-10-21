//go:build database_env_active
// +build database_env_active

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
	"os"
	"strconv"
	"testing"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/stretchr/testify/assert"
)

func TestDatabasePostgresAuth(t *testing.T) {
	postgresHost := os.Getenv("POSTGRES_HOST")
	postgresPort := os.Getenv("POSTGRES_PORT")
	postgresPassword := os.Getenv("POSTGRES_PWD")
	if !assert.NotEmpty(t, postgresHost) {
		return
	}
	assert.NotEmpty(t, postgresPort)
	port, err := strconv.Atoi(postgresPort)
	if !assert.NoError(t, err) {
		return
	}
	pg := fmt.Sprintf("postgres://<user>:<password>@%s:%d/<database>", postgresHost, port)

	RegisterDatabaseForAuth("pgx", pg, "SELECT 1")

	err = PerDatabase("bitgarten", "admin", postgresPassword)
	if !assert.NoError(t, err) {
		fmt.Println("Unwantend error:", err)
	}
	err = PerDatabase("bitgarten", "admin", "xxx")
	assert.Error(t, err)
	assert.Equal(t, "password authentication failed for user", err.Error())

}

func TestDatabaseMySQLAuth(t *testing.T) {
	mysqlHost := os.Getenv("MYSQL_HOST")
	mysqlPort := os.Getenv("MYSQL_PORT")
	mysqlPassword := os.Getenv("MYSQL_PWD")
	if !assert.NotEmpty(t, mysqlHost) {
		return
	}
	assert.NotEmpty(t, mysqlPort)
	port, err := strconv.Atoi(mysqlPort)
	if !assert.NoError(t, err) {
		return
	}
	mysql := fmt.Sprintf("<user>:<password>@tcp(%s:%d)/<database>", mysqlHost, port)

	RegisterDatabaseForAuth("mysql", mysql, "SELECT 1")

	err = PerDatabase("Bitgarten", "admin", mysqlPassword)
	if !assert.NoError(t, err) {
		fmt.Println("Unwantend error:", err)
	}
	err = PerDatabase("Bitgarten", "admin", "xxx")
	assert.Error(t, err)
	assert.Equal(t, "password authentication failed for user", err.Error())

}
