import requests

URL = "https://localhost:9443/"
CA_CERT = "ca.crt"
FAKE_CERT = ("fake.crt", "fake.key")  # Presenting a certificate NOT signed by the lab CA

def simulate_attack():
    print(f"🕵️‍♂️ Attempting unauthorized mTLS connection to {URL}...")
    try:
        # The attacker presents a certificate, but it's signed by themselves, not our CA
        response = requests.get(URL, verify=CA_CERT, cert=FAKE_CERT, timeout=5)
        print(f"⚠️ Security Breach! Server accepted the connection: {response.json()}")
    except requests.exceptions.SSLError as ssl_err:
        print("\n🛡️ SUCCESS: Connection blocked by the server at the TLS handshake level!")
        print(f"Reason: {ssl_err}")
    except Exception as e:
        print(f"\nBlocked or failed: {e}")

if __name__ == "__main__":
    simulate_attack()
