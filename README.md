# MLE Core

A professional, zero-configuration Message Level Encryption (MLE) engine for Python. It provides project-agnostic utility functions to encrypt and decrypt Nested JWTs (JWE + JWS).

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

## Quick Start

### 1. Setup Keys
The library automatically looks for `MLE_SERVER_PRIVATE_KEY` and `MLE_SERVER_PUBLIC_KEY` in your environment. If not found, it checks the `keys/` folder or **generates new ones automatically**.

### 2. Usage

```python
import mle_core

# --- Communication with Frontend ---

# Encrypt data for a specific client
encrypted_token = mle_core.encrypt_for_client(
    data={"message": "Hello World"},
    client_public_key=USER_PUBLIC_KEY
)

# Decrypt data received from a client
original_data = mle_core.decrypt_from_client(
    token=ENCRYPTED_TOKEN_FROM_CLIENT,
    client_public_key=USER_PUBLIC_KEY
)

# --- Internal Security ---

# Encrypt data that only the server can read (e.g. Access Tokens)
internal_token = mle_core.encrypt_internal(data={"user_id": 123})

# Decrypt internal data
data = mle_core.decrypt_internal(internal_token)

# --- Handshake ---

# Get the server's public key to share with the frontend
print(mle_core.SERVER_PUBLIC_KEY)
```

## Environment Variables
- `MLE_SERVER_PRIVATE_KEY`: Your Server's RSA Private Key (PEM format).
- `MLE_SERVER_PUBLIC_KEY`: Your Server's RSA Public Key (PEM format).
