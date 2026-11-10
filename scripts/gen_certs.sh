#!/usr/bin/env bash
# Generate lab CA, server cert, client cert, and an untrusted attacker cert.
set -euo pipefail
cd "$(dirname "$0")/.."

openssl req -x509 -new -newkey rsa:4096 -nodes -days 365 \
  -keyout ca.key -out ca.crt -subj "/CN=mTLS Lab CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

cat > server.ext <<EXT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EXT
openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=localhost" 2>/dev/null
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 365 -extfile server.ext 2>/dev/null

cat > client.ext <<EXT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EXT
openssl req -new -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/CN=mtls-client" 2>/dev/null
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days 365 -extfile client.ext 2>/dev/null

openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
  -keyout fake.key -out fake.crt -subj "/CN=attacker" 2>/dev/null

rm -f server.csr client.csr server.ext client.ext ca.srl
openssl verify -CAfile ca.crt server.crt client.crt
if openssl verify -CAfile ca.crt fake.crt >/dev/null 2>&1; then
  echo "ERROR: fake.crt unexpectedly verifies against the lab CA"; exit 1
fi
echo "Certificates generated."
