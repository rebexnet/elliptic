#!/bin/sh

if [ ! -f .paket/paket.exe ]; then
    .paket/paket.bootstrapper.exe
fi

# dotnet build fails if the vars below are set, for some reason (probably a bug)
unset TMP
unset TEMP

.paket/paket.exe restore
winpty packages/NAnt/tools/NAnt.exe $1 $2 $3
