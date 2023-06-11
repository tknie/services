package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckUser(t *testing.T) {
	err := LoadUsers(UserRole, "${CURDIR}/files/users-test.xml")
	assert.NoError(t, err)
	err = LoadUsers(AdministratorRole, "${CURDIR}/files/administrators-test.xml")
	assert.NoError(t, err)
	assert.False(t, ValidUser(UserRole, false, "", "abc"))
	assert.False(t, ValidUser(UserRole, false, "tkn", ""))
	assert.True(t, ValidUser(UserRole, false, "user1", "db"))
	assert.False(t, ValidUser(UserRole, false, "user1", "audit_data"))
	assert.True(t, ValidUser(UserRole, false, "admin", "audit_data"))
	assert.False(t, ValidUser(UserRole, false, "tkn", "audit_data"))
	assert.True(t, ValidUser(AdministratorRole, false, "tkn", "audit_data"))
	assert.True(t, ValidUser(AdministratorRole, true, "tkn", "audit_data"))
	assert.False(t, ValidUser(AdministratorRole, true, "user1", "abc"))
	assert.True(t, ValidAdmin("admin"))
	assert.False(t, ValidAdmin("user1"))
	assert.False(t, ValidAdmin(""))
}
