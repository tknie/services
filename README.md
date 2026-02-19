# Services collection

## Introduction

This project contains a set of services used for programming

* authorization and authentication
* services creating runlevel daemons
* pid file creation

## PID file

Following method will create a pid file

```go
err:=CreatePidFile("file.pid)
```

Read of PID file with

```go
err:=ReadPidFile("file.pid)
```

Delete of PID file with

```go
err:=DeletePidFile("file.pid)
```

## Authentication

* Login parameters for different password checks
  * Realm password file
  * PAM authentication
  * LDAP password checks
  * [Open] First OpenID implementation started
  * Database authentication (send user authentication to database)
* JSON Web token creation and validation certification dependent tokens

## Documentation

API documentation can be read at [github doc](https://pkg.go.dev/github.com/tknie/services#section-readme).
