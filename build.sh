#!/usr/bin/env bash
set -e

echo "▶ Installing Java 21..."
apt-get update -qq
apt-get install -y -qq openjdk-21-jre-headless

echo "▶ Java version:"
java -version

echo "▶ Creating tools directory..."
mkdir -p tools

echo "▶ Downloading apktool 2.11.1..."
curl -sSL \
  "https://github.com/iBotPeaches/Apktool/releases/download/v2.11.1/apktool_2.11.1.jar" \
  -o tools/apktool.jar

echo "▶ Downloading uber-apk-signer 1.3.0..."
curl -sSL \
  "https://github.com/patrickfav/uber-apk-signer/releases/download/v1.3.0/uber-apk-signer-1.3.0.jar" \
  -o tools/uber-signer.jar

echo "▶ Verifying tools..."
java -jar tools/apktool.jar --version
java -jar tools/uber-signer.jar --version

echo "▶ Installing Python deps..."
pip install -r requirements.txt

echo "▶ Generating debug keystore..."
keytool -genkeypair \
  -keystore tools/debug.keystore \
  -alias debugkey \
  -keyalg RSA -keysize 2048 -validity 10000 \
  -storepass android -keypass android \
  -dname "CN=Debug, OU=Android, O=Debug, L=Debug, ST=Debug, C=US" 2>/dev/null || true

echo "✓ Build complete"
