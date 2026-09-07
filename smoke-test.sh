#!/usr/bin/env bash
# Compile src + test and run the self-contained smoke test (no keystore, no TLS).
set -euo pipefail
cd "$(dirname "$0")"
rm -rf out-test
mkdir -p out-test
find src test -name '*.java' > sources-test.txt
javac -source 8 -target 8 -Xlint:none -d out-test @sources-test.txt
rm -f sources-test.txt
java -cp out-test com.kokovpn.stealth.server.SmokeTest
