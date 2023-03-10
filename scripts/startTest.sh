#!/bin/sh

rm logs/*
make test-build
ENABLE_DEBUG=${ENABLE_DEBUG:-0}
DYLD_LIBRARY_PATH=${ACLDIR}/lib
CURDIR=`pwd`
TESTFILES=${CURDIR}/files
LOGPATH=${CURDIR}/logs
export DYLD_LIBRARY_PATH ENABLE_DEBUG CURDIR
export TESTFILES LOGPATH

GOOS=`go env GOOS`
GOARCH=`go env GOARCH`
TEST_EXECUTE=bin/tests/${GOOS}_${GOARCH}/common.test

if [ $# -gt 1 ]; then
   TEST_EXECUTE=bin/tests/${GOOS}_${GOARCH}/$1.test
   shift
fi
PARA=
if [ $# -gt 0 ]; then
   PARA="-test.run $*"
else
   echo "Start all tests"
fi

${TEST_EXECUTE} -test.v ${PARA}
