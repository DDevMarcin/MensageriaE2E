#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p certs

PASS="${SERVER_KEYSTORE_PASS:-changeit}"
P12="certs/server.p12"
CRT="certs/server.crt"

rm -f "$P12" "$CRT"

keytool -genkeypair \
    -alias server \
    -keyalg RSA \
    -keysize 2048 \
    -sigalg SHA256withRSA \
    -validity 365 \
    -dname "CN=localhost" \
    -keystore "$P12" \
    -storetype PKCS12 \
    -storepass "$PASS"

keytool -exportcert \
    -alias server \
    -keystore "$P12" \
    -storepass "$PASS" \
    -file "$CRT"

echo "Certificados gerados em $P12 (privado) e $CRT (publico DER)."

