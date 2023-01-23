package services

import (
	"embed"
	"path"

	"github.com/tknie/errorrepo"
)

//go:embed messages
var embedFiles embed.FS

func init() {
	fss, err := embedFiles.ReadDir("messages")
	if err != nil {
		panic("Internal config load error: " + err.Error())
	}
	for _, f := range fss {
		if f.Type().IsRegular() {
			byteValue, err := embedFiles.ReadFile("messages/" + f.Name())
			if err != nil {
				panic("Internal config load error: " + err.Error())
			}
			lang := path.Ext(f.Name())
			errorrepo.RegisterMessage(lang[1:], string(byteValue))
		}
	}

}

// NewError wrap error messages to initialize error list
func NewError(msgID string, args ...interface{}) error {
	return errorrepo.NewError(msgID, args...)
}
