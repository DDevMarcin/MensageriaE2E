#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p out

SOURCES_FILE="out/sources.txt"
find src test -name "*.java" > "$SOURCES_FILE"

javac -Xlint:all --release 21 -encoding UTF-8 -d out @"$SOURCES_FILE"
rm -f "$SOURCES_FILE"

