#
# Copyright 2022-2023 Thorsten A. Knieling
#
# SPDX-License-Identifier: Apache-2.0
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#

GOARCH            ?= $(shell $(GO) env GOARCH)
GOOS              ?= $(shell $(GO) env GOOS)
GOEXE             ?= $(shell $(GO) env GOEXE)
GOBIN             ?= $(HOME)/go/bin

PACKAGE     = github.com/tknie/services
TESTPKGSDIR = . auth service
DATE       ?= $(shell date +%FT%T%z)
VERSION    ?= $(shell git describe --tags --always --dirty --match=v* 2> /dev/null || \
			cat $(CURDIR)/.version 2> /dev/null || echo v0)
PRODVERSION        = $(shell echo $(VERSION)|sed 's/\([[:digit:]]\)\.\([[:digit:]]\)\.\([[:digit:]]\)\.\([[:digit:]]\).*/v\1.\2.\3.\4/g')
BIN                = $(CURDIR)/bin/$(GOOS)_$(GOARCH)
BINTOOLS           = $(CURDIR)/bin/tools/$(GOOS)_$(GOARCH)
BINTESTS           = $(CURDIR)/bin/tests/$(GOOS)_$(GOARCH)
PROMOTE            = $(CURDIR)/promote/$(GOOS)_$(GOARCH)
LOGPATH            = $(CURDIR)/logs
CURLOGPATH         = $(CURDIR)/logs
NETWORK           ?= xx:30011
TESTOUTPUT         = $(CURDIR)/test
MESSAGES           = $(CURDIR)/messages
EXECS              = $(BIN)/cmd/service
OBJECTS            = *.go auth/*.go service/*.go
ENABLE_DEBUG      ?= 0
ARTIFACTORY       ?= http://tiger:32000
ARTIFACTORY_PASS  ?= admin:1234

export CGO_CFLAGS
export CGO_LDFLAGS
export ENABLE_DEBUG
export LOGPATH
export PORT TLS_PORT HOST TLS_HOST
export TLS_CERTIFICATE TLS_PRIVATE_KEY

include $(CURDIR)/make/common.mk

.PHONY: clean
clean: cleanModules cleanVendor cleanModels cleanCommon ; $(info $(M) cleaning…)    @ ## Cleanup everything
	@rm -rf restadmin.test jobs.test auth.test
	@rm -rf bin pkg logs test promote
	@rm -rf test/tests.* test/coverage.*

cleanVendor: ; $(info $(M) cleaning vendor…)    @ ## Cleanup vendor
	@rm -rf $(CURDIR)/vendor

cleanModels: ; $(info $(M) cleaning models…)    @ ## Cleanup models
	@rm -rf $(CURDIR)/models $(CURDIR)/client
	@rm -rf $(CURDIR)/restapi/[!cng]*
	@rm -rf $(CURDIR)/restapi/operations

promote: test-build ; $(info $(M) package for promotion…) @ ## package for promotion
	if [ ! -d $(CURDIR)/promote ]; then mkdir $(CURDIR)/promote; fi; \
	if [ ! -d $(PROMOTE) ]; then mkdir $(PROMOTE); fi

upload: ; $(info $(M) uploading…) @ ## uploading packages
