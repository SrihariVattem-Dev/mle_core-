"""
MLE CORE - GENERIC ENCRYPTION ENGINE
------------------------------------
This library provides project-agnostic utility functions to encrypt and decrypt Nested JWTs.
It automatically handles key management and configuration.

REQUIRED PACKAGES:
pip install python-jose[cryptography] jwcrypto
"""

import json
from jose import jwt
from jwcrypto import jwk, jwe
from datetime import datetime, timedelta
import os
from typing import Dict, Any
from dotenv import load_dotenv

load_dotenv()

MLE_ENABLED = os.getenv("MLE_ENABLED", "True").lower() in ("true", "1", "yes")

class MLEHandler:
    def __init__(self, server_private_key_pem: str, server_public_key_pem: str, algorithm: str = "RS256"):
        """Initialize the handler with the Server's RSA key pair."""
        self.server_private_key = server_private_key_pem
        self.server_public_key = server_public_key_pem
        self.algorithm = algorithm

    @classmethod
    def from_files(cls, private_key_path: str, public_key_path: str, algorithm: str = "RS256"):
        """Initialize from PEM files."""
        with open(private_key_path, "r") as f:
            private_key = f.read()
        with open(public_key_path, "r") as f:
            public_key = f.read()
        return cls(private_key, public_key, algorithm)

    # ==========================================
    # PURE CRYPTOGRAPHY ENGINE
    # ==========================================

    def encrypt_for_client(self, data: Dict[str, Any], client_public_key_pem: str) -> str:
        """
        Signs with Server Private Key, Encrypts with Client Public Key.
        (Use this for sending data TO the frontend)
        """
        payload = data.copy()
        payload["exp"] = datetime.utcnow() + timedelta(minutes=30)
        signed_token = jwt.encode(
            payload,
            self.server_private_key,
            algorithm=self.algorithm,
        )

        client_key = jwk.JWK.from_pem(client_public_key_pem.encode())
        encrypted = jwe.JWE(
            signed_token.encode(),
            protected={"alg": "RSA-OAEP-256", "enc": "A256GCM", "zip": "DEF", "cty": "JWT"}
        )
        encrypted.add_recipient(client_key)
        
        return encrypted.serialize(compact=True)

    def decrypt_from_client(self, encrypted_token: str, client_public_key_pem: str) -> Dict[str, Any]:
        """
        Decrypts with Server Private Key, Verifies with Client Public Key.
        (Use this for reading data FROM the frontend)
        """
        server_key = jwk.JWK.from_pem(self.server_private_key.encode())
        decrypted = jwe.JWE()
        decrypted.deserialize(encrypted_token)
        decrypted.decrypt(server_key)
        signed_token = decrypted.payload.decode()

        try:
            payload = jwt.decode(
                signed_token,
                client_public_key_pem,
                algorithms=[self.algorithm],
                options={"verify_aud": False}
            )
            return payload
        except Exception as e:
            raise Exception(f"Decryption/Verification failed: {str(e)}")

    def encrypt_internal(self, data: Dict[str, Any]) -> str:
        """Encrypts data using only the server's keys."""
        return self.encrypt_for_client(data, self.server_public_key)

    def decrypt_internal(self, encrypted_token: str) -> Dict[str, Any]:
        """Decrypts data using only the server's keys."""
        return self.decrypt_from_client(encrypted_token, self.server_public_key)

# ==========================================
# AUTOMATIC SETUP & KEY GENERATION
# ==========================================

def _setup_keys():
    """Tries to load keys from Env or Files, or generates them if missing."""
    private_key = os.getenv("MLE_SERVER_PRIVATE_KEY")
    public_key = os.getenv("MLE_SERVER_PUBLIC_KEY")

    if not private_key or not public_key:
        if os.path.exists("keys/server_private.pem") and os.path.exists("keys/server_public.pem"):
            with open("keys/server_private.pem", "r") as f: private_key = f.read()
            with open("keys/server_public.pem", "r") as f: public_key = f.read()

    if not private_key or not public_key:
        print("MLE Core: No keys found. Generating new RSA pair...")
        from jwcrypto import jwk
        key = jwk.JWK.generate(kty='RSA', size=2048)
        
        private_key = key.export_to_pem(private_key=True, password=None).decode()
        public_key = key.export_to_pem(private_key=False).decode()

        os.makedirs("keys", exist_ok=True)
        with open("keys/server_private.pem", "w") as f: f.write(private_key)
        with open("keys/server_public.pem", "w") as f: f.write(public_key)
        print("MLE Core: Keys automatically saved to 'keys/' folder.")

    return private_key, public_key

# Global instance for easy use
_keys = _setup_keys()
SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY = _keys
_mle_instance = MLEHandler(SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY)

# ==========================================
# EXPOSED ENGINE FUNCTIONS
# ==========================================

def encrypt_for_client(data: dict, client_public_key: str):
    if not MLE_ENABLED:
        return data
    return _mle_instance.encrypt_for_client(data, client_public_key)

def decrypt_from_client(token: str, client_public_key: str):
    if not MLE_ENABLED:
        if isinstance(token, dict):
            return token
        try:
            return json.loads(token)
        except Exception:
            return token
    
    return _mle_instance.decrypt_from_client(token, client_public_key)

def encrypt_internal(data: dict):
    if not MLE_ENABLED:
        return json.dumps(data)

    return _mle_instance.encrypt_internal(data)

def decrypt_internal(token: str):
    if not MLE_ENABLED:
        if isinstance(token, dict):
            return token
        try:
            return json.loads(token)
        except Exception:
            return token
    return _mle_instance.decrypt_internal(token)