# MLE Core

A professional, zero-configuration Message Level Encryption (MLE) engine for Python. It provides project-agnostic utility functions to encrypt and decrypt Nested JWTs (JWE + JWS), and a generic, drop-in transparent middleware for FastAPI.

## Features
* **Zero Dependencies on Frameworks**: Can be used in FastAPI, Flask, Django, or pure Python scripts.
* **Stateless**: Purely mathematical. It does not touch your database or file system.
* **Nested JWT Flow**:
  * **Decrypts Client Requests**: Unpacks JWE (with Server Private Key) -> Verifies JWS (with Client Public Key).
  * **Encrypts Server Responses**: Signs JWS (with Server Private Key) -> Encrypts JWE (with Client Public Key).
* **Transparent ASGI Middleware**: Decrypts incoming request payloads/query params and encrypts outgoing responses transparently.

## Installation

```bash
pip install git+https://github.com/SrihariVattem-Dev/mle_core-.git
```

## Quick Start

### 1. Setup Keys
The library automatically looks for `MLE_SERVER_PRIVATE_KEY` and `MLE_SERVER_PUBLIC_KEY` in your environment. If not found, it checks the `keys/` folder or **generates new ones automatically**.

### 2. Manual Cryptography Usage

```python
import mle_core

# --- Communication with Frontend ---
encrypted_token = mle_core.encrypt_for_client(
    data={"message": "Hello World"},
    client_public_key=USER_PUBLIC_KEY
)

original_data = mle_core.decrypt_from_client(
    token=ENCRYPTED_TOKEN_FROM_CLIENT,
    client_public_key=USER_PUBLIC_KEY
)

# --- Internal Security ---
internal_token = mle_core.encrypt_internal(data={"user_id": 123})
data = mle_core.decrypt_internal(internal_token)

# --- Handshake ---
print(mle_core.SERVER_PUBLIC_KEY)
```

---

## 🛡️ Transparent FastAPI Middleware Usage

`mle_core` includes a generic `MLEMiddleware` for FastAPI. It uses a **Key Resolver callback** to avoid locking you into any specific database, ORM, or token implementation.

### What to write in your project's `main.py`:

```python
from fastapi import FastAPI, Request
from mle_core import MLEMiddleware
# (Import your own project dependencies below)
from database import SessionLocal
from models import User
from utils.jwt_handler import validate_server_access_token

app = FastAPI()

# 1. Define your project's specific public key resolver
async def resolve_client_public_key(request: Request) -> str | None:
    """
    Decodes the Bearer token, checks authentication, and returns the 
    user's stored public key. If this returns None, the middleware 
    transparently bypasses encryption for this request (e.g., login/register).
    """
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
        
    token = auth_header.split(" ", 1)[1]
    try:
        # Decode your access token (e.g., standard HS256 JWT)
        payload = validate_server_access_token(token)
        email = payload.get("email")
        if not email:
            return None
            
        # Open your DB session, query your user, and return their client_public_key
        db = SessionLocal()
        try:
            user = db.query(User).filter(User.email == email).first()
            return user.client_public_key if user else None
        finally:
            db.close()
    except Exception:
        return None

# 2. Add the MLEMiddleware and inject the callback
app.add_middleware(MLEMiddleware, key_resolver=resolve_client_public_key)
```

### How the Middleware Handles Requests transparently:
1. **GET Requests:** Automatically decrypts `?encrypted_data=ey...` and rewrites the query parameters in-memory. Your router reads standard plain query arguments!
2. **POST Requests:** Intercepts and decrypts `{"encrypted_data": "ey..."}`, patches headers (`Content-Length`/`Content-Type`), and mounts the raw JSON body. Your router reads native Pydantic objects!
3. **Responses:** Intercepts outgoing server responses, encrypts them using the resolved `client_public_key`, and packages them into a `{"secure_response": "ey..."}` envelope.

---

## Environment Variables
- `MLE_SERVER_PRIVATE_KEY`: Your Server's RSA Private Key (PEM format).
- `MLE_SERVER_PUBLIC_KEY`: Your Server's RSA Public Key (PEM format).
- `MLE_ENABLED`: Toggle MLE feature globally (`True`/`False`). Defaults to `True`.
