import ssl
from fastapi import FastAPI

app = FastAPI(title="mTLS Security Lab")

@app.get("/")
def read_root():
    return {
        "status": "Success", 
        "message": "Mutual TLS (mTLS) authentication passed successfully!"
    }

if __name__ == "__main__":
    import uvicorn

    print("🚀 Starting secure mTLS server on https://127.0.0.1:8000")
    
    # Using explicit file paths so Uvicorn can handle reload=True cleanly
    uvicorn.run(
        "server:app", 
        host="127.0.0.1", 
        port=8000, 
        ssl_keyfile="server.key",
        ssl_certfile="server.crt",
        ssl_ca_certs="ca.crt",
        ssl_cert_reqs=int(ssl.CERT_REQUIRED),
        reload=True
    )
