#!/usr/bin/env bash
# Generate certificates for the e-commerce mTLS lab.
#
# Two separate trust domains, as in a real deployment:
#   Internal CA  - issues identities for our own services (edge, orders, payments, catalog)
#   PSP CA       - the payment provider's CA; issues its gateway cert and our merchant client cert
# Plus an attacker certificate that is self-signed and trusted by no one.
set -euo pipefail
LAB="$(cd "$(dirname "$0")/.." && pwd)"
CERTS="$LAB/certs"
mkdir -p "$CERTS"
cd "$CERTS"

make_ca() { # name, subject
  openssl req -x509 -new -newkey rsa:3072 -nodes -days 365 \
    -keyout "$1.key" -out "$1.crt" -subj "/CN=$2" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
}

make_leaf() { # ca, name(CN), eku, san
  local ca="$1" name="$2" eku="$3" san="$4"
  openssl req -new -newkey rsa:2048 -nodes -keyout "$name.key" -out "$name.csr" \
    -subj "/CN=$name" 2>/dev/null
  {
    echo "basicConstraints=critical,CA:FALSE"
    echo "keyUsage=critical,digitalSignature,keyEncipherment"
    echo "extendedKeyUsage=$eku"
    echo "subjectKeyIdentifier=hash"
    echo "authorityKeyIdentifier=keyid,issuer"
    if [ -n "$san" ]; then echo "subjectAltName=$san"; fi
  } > "$name.ext"
  openssl x509 -req -in "$name.csr" -CA "$ca.crt" -CAkey "$ca.key" -CAcreateserial \
    -out "$name.crt" -days 90 -extfile "$name.ext" 2>/dev/null
  rm -f "$name.csr" "$name.ext"
}

LOCAL="DNS:localhost,IP:127.0.0.1"

# Internal trust domain
make_ca internal-ca "Shop Internal CA"
for svc in edge orders payments catalog; do
  make_leaf internal-ca "$svc" "serverAuth,clientAuth" "DNS:$svc.internal,$LOCAL"
done

# Payment provider trust domain
make_ca psp-ca "Mock PSP CA"
make_leaf psp-ca psp-gateway "serverAuth" "DNS:gateway.psp.example,$LOCAL"
make_leaf psp-ca merchant-payments "clientAuth" ""

# Attacker: self-signed, chains to nothing we trust
openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
  -keyout attacker.key -out attacker.crt -subj "/CN=orders" 2>/dev/null

rm -f ./*.srl
chmod 600 ./*.key

# Sanity checks
openssl verify -CAfile internal-ca.crt edge.crt orders.crt payments.crt catalog.crt
openssl verify -CAfile psp-ca.crt psp-gateway.crt merchant-payments.crt
for pair in "internal-ca attacker" "psp-ca orders" "internal-ca merchant-payments"; do
  set -- $pair
  if openssl verify -CAfile "$1.crt" "$2.crt" >/dev/null 2>&1; then
    echo "ERROR: $2.crt must NOT verify against $1.crt"; exit 1
  fi
done
echo "Certificates generated in $CERTS"
