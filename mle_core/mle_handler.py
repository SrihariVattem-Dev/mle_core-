"""
MANUAL UTILITY APPROACH
-----------------------
This folder contains the standalone MLEHandler class. 
It is database-agnostic and provides pure utility functions to encrypt and decrypt Nested JWTs.

REQUIRED PACKAGES:
pip install python-jose jwcrypto
"""

from jose import jwt, JWTError, ExpiredSignatureError
from jwcrypto import jwk, jwe
from datetime import datetime, timedelta
import json
from typing import Dict, Any

class MLEHandler:
    def __init__(self, server_private_key_pem: str, server_public_key_pem: str, algorithm: str = "RS256"):
        """
        Initialize the handler with the Server's RSA key pair.
        """
        self.server_private_key = server_private_key_pem
        self.server_public_key = server_public_key_pem
        self.algorithm = algorithm

    # ==========================================
    # CLIENT → SERVER FLOW (DECRYPT)
    # ==========================================
    def decrypt_client_request(self, encrypted_token: str, client_public_key_pem: str) -> Dict[str, Any]:
        """
        Decrypts an incoming request from the frontend.
        1. Decrypts JWE using Server's Private Key.
        2. Verifies JWS using Client's Public Key.
        """
        # 1. DECRYPT
        server_key = jwk.JWK.from_pem(self.server_private_key.encode())
        decrypted = jwe.JWE()
        decrypted.deserialize(encrypted_token)
        decrypted.decrypt(server_key)
        signed_token = decrypted.payload.decode()

        # 2. VERIFY
        try:
            payload = jwt.decode(
                signed_token,
                client_public_key_pem,
                algorithms=[self.algorithm],
                options={"verify_aud": False} # SDK sets 'nested-jwt-sdk-server' by default
            )
            return payload
        except ExpiredSignatureError:
            raise Exception("Secure request has expired (exp claim failed)")
        except JWTError as e:
            raise Exception(f"Signature verification failed: {str(e)}")
        except Exception as e:
            raise Exception(f"Failed to verify request: {str(e)}")

    # ==========================================
    # SERVER → CLIENT FLOW (ENCRYPT)
    # ==========================================
    def encrypt_server_response(self, data: Dict[str, Any], client_public_key_pem: str) -> str:
        """
        Encrypts an outgoing response meant for the frontend.
        1. Signs data using Server's Private Key.
        2. Encrypts signed data using Client's Public Key.
        """
        # 1. SIGN
        payload = data.copy()
        payload["exp"] = datetime.utcnow() + timedelta(minutes=30)
        signed_token = jwt.encode(
            payload,
            self.server_private_key,
            algorithm=self.algorithm,
        )

        # 2. ENCRYPT
        client_key = jwk.JWK.from_pem(client_public_key_pem.encode())
        encrypted = jwe.JWE(
            signed_token.encode(),
            protected={"alg": "RSA-OAEP-256", "enc": "A256GCM", "cty": "JWT"}
        )
        encrypted.add_recipient(client_key)
        
        return encrypted.serialize(compact=True)

    # ==========================================
    # SERVER-ONLY FLOW (ACCESS TOKENS)
    # ==========================================
    def generate_server_access_token(self, data: Dict[str, Any]) -> str:
        """Encrypts data using ONLY the server's keys (For Auth tokens)."""
        return self.encrypt_server_response(data, self.server_public_key)

    def validate_server_access_token(self, encrypted_token: str) -> Dict[str, Any]:
        """Decrypts data using ONLY the server's keys."""
        return self.decrypt_client_request(encrypted_token, self.server_public_key)
