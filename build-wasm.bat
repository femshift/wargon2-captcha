@echo off
echo Building WASM module...

REM
set GOOS=js
set GOARCH=wasm

REM
cd wasm
go build -o ../web/fingerprint.wasm main.go

REM
for /f "delims=" %%i in ('go env GOROOT') do set GOROOT=%%i
copy "%GOROOT%\misc\wasm\wasm_exec.js" ..\web\

echo WASM module built successfully!
echo Files generated:
echo   - web/fingerprint.wasm
echo   - web/wasm_exec.js 