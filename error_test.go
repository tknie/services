package services

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrors(t *testing.T) {
	assert.Equal(t, "", NewError("SYS00001").Error())
	assert.Equal(t, "", NewError("SYS00002").Error())
	assert.Equal(t, "", NewError("SYS00003").Error())
	assert.Equal(t, "", NewError("SYS00004").Error())
	assert.Equal(t, "", NewError("SYS00005").Error())
	assert.Equal(t, "", NewError("SYS00006").Error())
	assert.Equal(t, "", NewError("SYS00007").Error())
	assert.Equal(t, "", NewError("SYS00008").Error())

}
