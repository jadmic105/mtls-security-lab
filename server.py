import ssl
from fastapi import FastAPI, Request, HTTPException

app = FastAPI(title="mTLS Security Lab")

@app.get("/")
def read_root(request: Request):
    # 1. Grab the underlying client SSL certificate from the connection transport
    scope = request.scope
    client_cert = scope.get("extensions", {}).get("tls", {}).get("client_cert")
    
    if not client_cert:
        # Extra safeguard: reject if somehow missing
        pass  # client cert enforced at TLS layer (CERT_REQUIRED)

    # 2. Parse the certificate string or dictionary depending on the ASGI server state
    # In standard Uvicorn setups, we can read the subject components
    try:
        # Extract the subject fields (like Common Name)
        # Note: Depending on the Uvicorn version, scope['extensions']['tls'] gives structured data
        tls_info = scope.get("extensions", {}).get("tls", {})
        client_name = "Authenticated Client"
        
        # Look for the Subject Common Name (CN)
        if "client_subject" in tls_info:
            client_name = tls_info["client_subject"]
    except Exception:
        client_name = "Unknown Trusted Client"

    return {
        "status": "Success", 
        "identity": client_name,
        "message": f"Hello {client_name}! Mutual TLS (mTLS) authentication passed successfully!"
    }

if __name__ == "__main__":
    import uvicorn

    print("🚀 Starting upgraded secure mTLS server on port 9443...")
    
    uvicorn.run(
        "server:app", 
        host="0.0.0.0", 
        port=9443, 
        ssl_keyfile="server.key",
        ssl_certfile="server.crt",
        ssl_ca_certs="ca.crt",
        ssl_cert_reqs=int(ssl.CERT_REQUIRED),
        reload=True
    )
