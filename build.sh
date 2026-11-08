#!/usr/bin/env bash
set -e

# ── Java 21 (Temurin JRE) via direct download — no apt required ──────────────
JDK_DIR="tools/jdk21"
mkdir -p tools

if [ ! -f "$JDK_DIR/bin/java" ]; then
  echo "▶ Downloading JDK 21 (Temurin JRE, x64 Linux)..."
  curl -sSL \
    "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.5%2B11/OpenJDK21U-jre_x64_linux_hotspot_21.0.5_11.tar.gz" \
    -o tools/jdk21.tar.gz
  mkdir -p "$JDK_DIR"
  tar -xzf tools/jdk21.tar.gz -C "$JDK_DIR" --strip-components=1
  rm tools/jdk21.tar.gz
else
  echo "▶ JDK 21 already present, skipping download."
fi

export JAVA_HOME="$(pwd)/$JDK_DIR"
export PATH="$JAVA_HOME/bin:$PATH"

echo "▶ Java version:"
java -version

# ── apktool + uber-apk-signer ─────────────────────────────────────────────────
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

# ── Python deps ───────────────────────────────────────────────────────────────
echo "▶ Installing Python deps..."
pip install -r requirements.txt

# ── Debug keystore ────────────────────────────────────────────────────────────
echo "▶ Generating debug keystore..."
keytool -genkeypair \
  -keystore tools/debug.keystore \
  -alias debugkey \
  -keyalg RSA -keysize 2048 -validity 10000 \
  -storepass android -keypass android \
  -dname "CN=Debug, OU=Android, O=Debug, L=Debug, ST=Debug, C=US" 2>/dev/null || true

echo "✓ Build complete"
