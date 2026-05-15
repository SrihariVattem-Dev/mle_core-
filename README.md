# MLE Core (Message Level Encryption)

A lightweight, purely mathematical, database-agnostic Python library for Message Level Encryption. 
This library provides a standalone utility to encrypt and decrypt **Nested JWTs** (JWS inside JWE) using `RSA-OAEP-256` and `RS256` for secure Client-Server communication.

## Features
* **Zero Dependencies on Frameworks**: Can be used in FastAPI, Flask, Django, or pure Python scripts.
* **Stateless**: Purely mathematical. It does not touch your database or file system.
* **Nested JWT Flow**:
  * **Decrypts Client Requests**: Unpacks JWE (with Server Private Key) -> Verifies JWS (with Client Public Key).
  * **Encrypts Server Responses**: Signs JWS (with Server Private Key) -> Encrypts JWE (with Client Public Key).

## Installation (As a Git Submodule)

To add this library to your main project (e.g., Farmvest):

1. Add the submodule to your project:
   ```bash
   git submodule add https://github.com/YourUsername/mle_core.git
   ```
2. Install the required cryptography packages:
   ```bash
   pip install -r mle_core/requirements.txt
   ```

## Usage Example

```python
from mle_core import MLEHandler

# 1. Initialize the handler with your Server's keys
mle = MLEHandler(
    server_private_key_pem="-----BEGIN PRIVATE KEY...-----",
    server_public_key_pem="-----BEGIN PUBLIC KEY...-----"
)

# 2. Decrypt an incoming request from the frontend
try:
    decrypted_data = mle.decrypt_client_request(
        encrypted_token=request_body.encrypted_payload,
        client_public_key_pem="-----BEGIN PUBLIC KEY...-----"
    )
    print("Securely received:", decrypted_data)
except Exception as e:
    print("Failed to decrypt or verify!", e)

# 3. Encrypt a secure response to send back
encrypted_response_string = mle.encrypt_server_response(
    data={"status": "success", "user_id": 123},
    client_public_key_pem="-----BEGIN PUBLIC KEY...-----"
)
```
