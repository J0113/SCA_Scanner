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

mkdir -p publish/release
mv publish/osx-arm64/SCAScanner  publish/release/SCAScanner-osx-arm64
mv publish/linux-x64/SCAScanner  publish/release/SCAScanner-linux-x64
mv publish/win-x64/SCAScanner.exe publish/release/SCAScanner-win-x64.exe

echo "Build complete:"
ls -lh publish/release/SCAScanner-osx-arm64 publish/release/SCAScanner-linux-x64 publish/release/SCAScanner-win-x64.exe
