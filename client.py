import requests

# Using localhost and the correct port explicitly
URL = "https://localhost:9443/"
CA_CERT = "ca.crt"
CLIENT_CERT = ("client.crt", "client.key")

def make_secure_request():
    print(f"🔒 Initiating secure mTLS request to {URL}...")
    try:
        response = requests.get(URL, verify=CA_CERT, cert=CLIENT_CERT)
        print("\n🎉 RESPONSE RECEIVED FROM SERVER:")
        print(f"Status Code: {response.status_code}")
        print(f"Data: {response.json()}")
    except requests.exceptions.SSLError as ssl_err:
        print(f"\n❌ SSL Handshake Failed: {ssl_err}")
    except Exception as e:
        print(f"\n❌ Connection Error: {e}")

if __name__ == "__main__":
    make_secure_request()
