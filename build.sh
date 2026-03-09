#!/usr/bin/env bash
set -euo pipefail

PROJECT="SCAScanner.csproj"
FLAGS="--self-contained true -p:PublishSingleFile=true -p:PublishTrimmed=false -c Release"

echo "Building SCAScanner — self-contained single-file executables"
echo

dotnet publish "$PROJECT" -r osx-arm64 $FLAGS -o publish/osx-arm64
echo

dotnet publish "$PROJECT" -r linux-x64 $FLAGS -o publish/linux-x64
echo

dotnet publish "$PROJECT" -r win-x64   $FLAGS -o publish/win-x64
echo

echo "Build complete:"
ls -lh publish/osx-arm64/SCAScanner publish/linux-x64/SCAScanner publish/win-x64/SCAScanner.exe
