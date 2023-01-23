# Common services

## Common

Central functionality for common tasks like

* Logging task central usage to define file names and debug level
  * error
  * info
  * debug
  * trace
* Central component to handle message database and output to a output file or central log files
* Loading of XML based configuration file used to define the configruation based on the application configuration structure. Update of configuration supported
* PID file creation processing. Creates, deletes or read PID file to handle corresponding operations for shutdown or check if process is still active
* Different standard output formatter of byte array data
* Evaluate environment variables and exchange references to define file path definitions

### Logging

```go
logging := &Logging{}
logging.InitTraceLogging()
```

### Messages

Load message defined as JSON buffer to be parsed by message processor. Message JSON format is

```JSON
{
    "Message":[
        {"Name":"SYS00029","Message":"Error opening server PID file: %s"},
        ]
}
```

The file content can be loaded with

```go
LoadMessage(msgBuffer)
```

To reference the message use

```go
err:=NewError("XXX00029","abc)
```

This will parse corresponding parameters and provied error instance

### PID file

Following method will create a pid file

```go
err:=common.CreatePidFile("file.pid)
```

Read of PID file with

```go
err:=common.ReadPidFile("file.pid)
```

Delete of PID file with

```go
err:=common.DeletePidFile("file.pid)
```

### Formatter

## Authentication

* Login parameters for different password checks
  * Realm password file
  * PAM authentication
  * LDAP password checks
  * [Open] First OpenID implementation started
* JSON Web token creation and validation certification dependent tokens

```go
service:=&AuthenticationServer{}
err:=service.Authenticate("admin","password")
// err equal nil is user valid and authenticated
```