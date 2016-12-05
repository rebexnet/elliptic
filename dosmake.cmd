@ECHO OFF

IF NOT EXIST .paket\paket.exe (
    ECHO Paket.exe not found - running paket bootstrapper
    .paket\paket.bootstrapper.exe
)

.paket\paket.exe restore
packages\NAnt\tools\NAnt.exe %1