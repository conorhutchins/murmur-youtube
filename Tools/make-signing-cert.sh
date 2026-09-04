#!/bin/bash
# One-time, per machine: a self-signed code-signing certificate so the app's signature —
# and with it the Accessibility grant — survives rebuilds.
#
# macOS keys each Accessibility grant to the code signature. An ad-hoc signature changes on
# every build, so without a stable identity every `make install` silently breaks the hotkey
# until the grant is reset and re-added. A Developer ID fixes that but costs money; for a
# local build a self-signed certificate does the same job for free.
#
# Expect two prompts: your login password once, to trust the certificate for code signing,
# and a keychain prompt the first time codesign uses the key — choose "Always Allow".
set -euo pipefail

NAME="Murmur Local Signing"
KEYCHAIN="$HOME/Library/Keychains/login.keychain-db"

if security find-identity -v -p codesigning | grep -q "\"$NAME\""; then
    echo "'$NAME' already exists — nothing to do"
    exit 0
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# An earlier run may have imported the certificate and then been cancelled at the trust
# prompt, so only generate and import when it isn't in the keychain yet.
if security find-certificate -c "$NAME" "$KEYCHAIN" >/dev/null 2>&1; then
    security find-certificate -c "$NAME" -p "$KEYCHAIN" > "$TMP/cert.pem"
else
    /usr/bin/openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -sha256 \
        -subj "/CN=$NAME" \
        -addext "keyUsage=critical,digitalSignature" \
        -addext "extendedKeyUsage=critical,codeSigning" \
        -addext "basicConstraints=critical,CA:false" \
        -keyout "$TMP/key.pem" -out "$TMP/cert.pem" 2>/dev/null

    /usr/bin/openssl pkcs12 -export -name "$NAME" -passout pass:x \
        -inkey "$TMP/key.pem" -in "$TMP/cert.pem" -out "$TMP/cert.p12"

    # -T lets codesign use the private key without a prompt on every build.
    security import "$TMP/cert.p12" -k "$KEYCHAIN" -P x \
        -T /usr/bin/codesign -T /usr/bin/security >/dev/null
fi

# Self-signed, so nothing vouches for it until you do. This is the password prompt.
security add-trusted-cert -p codeSign -k "$KEYCHAIN" "$TMP/cert.pem"

security find-identity -v -p codesigning | grep "\"$NAME\""
echo "Now run 'make install' and re-grant Accessibility one last time."
