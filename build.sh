#!/usr/bin/env bash
# Build the STEALTH server into ./out (production classes only, Java 8 compatible).
set -euo pipefail
cd "$(dirname "$0")"
rm -rf out
mkdir -p out
find src -name '*.java' > sources.txt
javac -source 8 -target 8 -Xlint:none -d out @sources.txt
rm -f sources.txt
echo "Built to ./out"
echo "Run:  java -cp out com.kokovpn.stealth.server.StealthServer --config server.properties"
