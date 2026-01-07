/*
* Copyright 2022-2026 Thorsten A. Knieling
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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecrypt(t *testing.T) {
	pwd, err := DecryptPassword("ZhzgZ7iJOO2oMjvXznX23+04FGBzqzgZYupNcZB4SC3t2JGa", "P0mYl5WyIYx1oTtTt0Yt8wwaTp/kM/12Um69o1xCy84")
	assert.NoError(t, err)
	assert.Equal(t, "testpass", pwd)
	pwd, err = DecryptPassword("/O6TPHIBhzwKLRD1isqdHPxw+D7Hz3L9o9p/p3UhU1j9kRla", "QHmmgz0B4wJgusuFSQ+uJzZGKixGIaYSEX1Se+6k/fU")
	assert.NoError(t, err)
	assert.Equal(t, "testpass", pwd)
	pwd, err = DecryptPassword("0I/sdR5KU/PwvzZTabjMibcXWGurdaFRWjoD81GDis3e/Ztj", "X6xbvdga1kY6m1gKVlINrTZKP7/qoPYM/GtfEdgIG1c")
	assert.NoError(t, err)
	assert.Equal(t, "testpass", pwd)
}
