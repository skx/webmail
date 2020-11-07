#!/bin/sh

# init modules
go mod init

# Ensure that we have `implant` for the moment, to generate
# static resources.
go get -u github.com/skx/implant
go generate

# Run golang tests - we have none.  oops.
go test ./...
