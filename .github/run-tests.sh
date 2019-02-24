#!/bin/sh

# init modules
go mod init

# Run golang tests - we have none.  oops.
go test ./...
