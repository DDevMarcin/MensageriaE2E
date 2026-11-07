@echo off
setlocal
cd /d "%~dp0\.."

if not exist certs mkdir certs

if defined SERVER_KEYSTORE_PASS (
    set "PASS=%SERVER_KEYSTORE_PASS%"
) else (
    set "PASS=changeit"
)

set "P12=certs\server.p12"
set "CRT=certs\server.crt"

if exist "%P12%" del /q "%P12%"
if exist "%CRT%" del /q "%CRT%"

keytool -genkeypair -alias server -keyalg RSA -keysize 2048 -sigalg SHA256withRSA -validity 365 -dname "CN=localhost" -keystore "%P12%" -storetype PKCS12 -storepass "%PASS%"
if errorlevel 1 exit /b %ERRORLEVEL%

keytool -exportcert -alias server -keystore "%P12%" -storepass "%PASS%" -file "%CRT%"
if errorlevel 1 exit /b %ERRORLEVEL%

echo Certificados gerados em %P12% (privado) e %CRT% (publico DER).
exit /b 0

