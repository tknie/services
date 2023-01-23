#!/bin/sh

LD_LIBRARY_PATH="$LD_LIBRARY_PATH:${ACLDIR}/lib"
DYLD_LIBRARY_PATH="$DYLD_LIBRARY_PATH:${ACLDIR}/lib:/lib:/usr/lib"
export LD_LIBRARY_PATH DYLD_LIBRARY_PATH

CGO_LDFLAGS="${CGO_LDFLAGS} ${CGO_EXT_LDFLAGS}"
export CGO_LDFLAGS
${GO} test --json -timeout ${TIMEOUT}s -count=1 -tags "release adalnk" -v $* ./auth
${GO} test --json -timeout ${TIMEOUT}s -count=1 -tags "release adalnk" -v $* ./common
