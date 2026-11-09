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

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    ssl_context.load_verify_locations(cafile="ca.crt")
    ssl_context.verify_mode = ssl.CERT_REQUIRED

    print("🚀 Starting secure mTLS server on https://127.0.0.1:8000")
    
    uvicorn.run(
        "server:app", 
        host="127.0.0.1", 
        port=8000, 
        ssl_context=ssl_context,
        reload=True
    )
