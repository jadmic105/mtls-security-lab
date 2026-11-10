# mTLS Security Lab

![mTLS tests](https://github.com/jadmic105/mtls-security-lab/actions/workflows/mtls-tests.yml/badge.svg)

A small lab that demonstrates **mutual TLS (mTLS)**: the server proves its identity to the client, and the client must prove its identity to the server with a certificate signed by a trusted CA. A simulated attacker presenting an untrusted certificate is rejected during the TLS handshake.

Built and tested on Ubuntu under WSL with OpenSSL 3 and Python 3.

## Repository contents

| File | Purpose |
|---|---|
| `server.py` | FastAPI app served by Uvicorn over HTTPS on port 9443, requiring a client certificate |
| `client.py` | Legitimate client that presents a CA-signed certificate |
| `attacker_client.py` | Attacker simulation that presents a self-signed certificate |
| `ca.crt`, `server.crt`, `client.crt` | Public certificates (private keys are **not** committed) |
| `fake.crt` | The attacker's self-signed certificate |

Private keys (`*.key`), CSRs (`*.csr`), serial files (`*.srl`) and `.venv/` are excluded by `.gitignore`. Generate your own keys with the steps below.

## 1. Setup

```bash
git clone https://github.com/jadmic105/mtls-security-lab.git
cd mtls-security-lab
python3 -m venv .venv
source .venv/bin/activate
pip install fastapi uvicorn requests
```

## 2. Generate the certificates

The extensions below are required. Python 3.13+ enables strict X.509 verification (`VERIFY_X509_STRICT`) by default, and without them it rejects the chain with `CA cert does not include key usage extension`.

### Certificate Authority

```bash
openssl req -x509 -new -newkey rsa:4096 -nodes -days 365 \
  -keyout ca.key -out ca.crt -subj "/CN=mTLS Lab CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
```

### Server certificate

```bash
openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=localhost"

cat > server.ext <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 365 -extfile server.ext
```

### Client certificate

```bash
openssl req -new -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/CN=mtls-client"

cat > client.ext <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days 365 -extfile client.ext
```

### Attacker certificate (self-signed, not trusted by the CA)

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
  -keyout fake.key -out fake.crt -subj "/CN=attacker"
```

### Verify

```bash
openssl verify -CAfile ca.crt server.crt client.crt   # both: OK
openssl verify -CAfile ca.crt fake.crt                # should FAIL
```

## 3. Run the lab

Use separate terminals, all in the project folder.

**Terminal 1: server**

```bash
python3 server.py
```

Leave it running. It listens on `https://localhost:9443`.

**Terminal 2: legitimate client**

```bash
python3 client.py
```

Expected: the request succeeds and the server's response is printed.

**Terminal 3: attacker**

```bash
python3 attacker_client.py
```

Expected: the TLS handshake is rejected (see results below).

Optional quick test without Python, using OpenSSL's built-in server:

```bash
openssl s_server -accept 9443 -cert server.crt -key server.key -CAfile ca.crt -Verify 1 -www
curl -v https://localhost:9443 --cacert ca.crt --cert client.crt --key client.key
```

## 4. Attacker test results

**Scenario:** an attacker who can reach the server but holds only a self-signed certificate (`fake.crt`) attempts to connect.

**Expected behavior:** the server rejects the client certificate during the TLS handshake because it is not signed by the trusted CA. No HTTP request reaches the application.

### Control: legitimate client (`client.py`)

```
🔒 Initiating secure mTLS request to https://localhost:9443/...

🎉 RESPONSE RECEIVED FROM SERVER:
Status Code: 200
Data: {'status': 'Success', 'identity': 'Authenticated Client', 'message': 'Hello Authenticated Client! Mutual TLS (mTLS) authentication passed successfully!'}
```

### Attack: self-signed certificate (`attacker_client.py`)

```
🕵️‍♂️ Attempting unauthorized mTLS connection to https://localhost:9443/...

Blocked or failed: ('Connection aborted.', RemoteDisconnected('Remote end closed connection without response'))
```

### Result

| Client | Certificate | Outcome |
|---|---|---|
| `client.py` | Signed by the lab CA | ✅ Handshake completed, HTTP **200** |
| `attacker_client.py` | Self-signed (`fake.crt`) | ✅ **Rejected during the TLS handshake**; no HTTP response |

The server runs with `ssl_cert_reqs=ssl.CERT_REQUIRED`. The attacker can reach the port, but the server terminates the handshake when the presented certificate does not chain to `ca.crt`, so the request never reaches the application. With TLS 1.3 the client certificate is verified at the end of the handshake, so Python's `requests` reports the rejection as `RemoteDisconnected` / `ConnectionResetError` rather than an `SSLError`.

The only variable between the two runs is the client certificate, so the rejection is attributable to mTLS.

> **Validity check:** a `Connection refused` error means the server was not running and the test is **not** valid. A real rejection is a handshake failure, connection reset, or remote disconnect *while the legitimate client succeeds*.

### Design note: where mTLS is enforced

Enforcement happens in the TLS layer (`CERT_REQUIRED`), not in the FastAPI route. An earlier version also checked for the client certificate inside the route and returned `403 Client certificate missing` for every request. Uvicorn does not expose the peer certificate to the ASGI app, so that check always failed. It was removed. To make per-client decisions in the app (for example by certificate CN), terminate TLS at a reverse proxy such as nginx or Envoy and forward the verified certificate details in a header.

## 5. Troubleshooting notes

| Symptom | Cause | Fix |
|---|---|---|
| `curl: (7) ... Connection refused` | Nothing is listening on that port | Start the server; confirm with `ss -ltn \| grep 9443` |
| `Failed to connect to 127.0.0.0` | Typo: loopback is `127.0.0.1` | Use `127.0.0.1` or `localhost` |
| `BIO_bind: Address already in use` | Another process (or Windows) holds the port | `sudo lsof -i :<port>`, or use another port |
| `CA cert does not include key usage extension` | Python 3.13+ strict X.509 checks | Regenerate the CA with `keyUsage` (section 2) |
| `Could not find the TLS certificate file` | Cert path wrong or file missing | Run from the project folder; generate the file |
| Server crashes with `FileNotFoundError` in `load_cert_chain` | Private keys not in the project folder (they are git-ignored) | Generate or copy `server.key` / `client.key` into the folder |
| Valid client gets `403 Client certificate missing` | App-level check for a peer cert that Uvicorn does not expose | Rely on `CERT_REQUIRED`; remove the in-route check |
| `python: command not found` | Ubuntu ships only `python3` | Use `python3`, or activate the venv |
| GitHub `push declined due to repository rule violations` | Secret scanning detected a private key | Remove keys from the commits, add `*.key` to `.gitignore` |

## Security notes

- Never commit private keys. Anyone with `ca.key` can issue certificates the server will trust.
- If a key was ever pushed, regenerate it. Deleting it from the repo does not remove it from git history.
- These certificates are for local testing only.
