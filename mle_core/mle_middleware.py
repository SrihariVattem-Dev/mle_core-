try:
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import Response
except ImportError:
    # Safe fallback if starlette/fastapi is not installed (e.g. non-ASGI projects)
    class BaseHTTPMiddleware:
        def __init__(self, app):
            self.app = app
    Request = None
    Response = None

import json
import urllib.parse
from . import mle_handler

class MLEMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, key_resolver):
        if Request is None:
            raise ImportError("Starlette/FastAPI must be installed to use MLEMiddleware.")
        super().__init__(app)
        self.key_resolver = key_resolver

    async def dispatch(self, request, call_next):
        try:
            client_public_key = await self.key_resolver(request)
        except Exception as e:
            print(f"[MLE] Key resolver failed: {e}")
            client_public_key = None

        if not client_public_key:
            return await call_next(request)

        # ── DECRYPT INCOMING GET REQUEST ──────────────────────────────────────
        if request.method == "GET" and "encrypted_data" in request.query_params:
            encrypted_data = request.query_params["encrypted_data"]
            try:
                decrypted = mle_handler.decrypt_from_client(encrypted_data, client_public_key)
                if isinstance(decrypted, dict):
                    new_qs = urllib.parse.urlencode(decrypted)
                    request.scope["query_string"] = new_qs.encode("utf-8")
            except Exception as e:
                print(f"[MLE] GET decryption failed: {e}")

        # ── DECRYPT INCOMING POST REQUEST ─────────────────────────────────────
        elif request.method == "POST":
            raw_body = await request.body()
            try:
                body_dict = json.loads(raw_body)
                encrypted_data = body_dict.get("encrypted_data")

                if encrypted_data:
                    decrypted = mle_handler.decrypt_from_client(encrypted_data, client_public_key)
                    new_body = json.dumps(decrypted).encode("utf-8")

                    # Correct Content-Length and Content-Type headers
                    new_headers = [
                        (k, v) for k, v in request.scope["headers"]
                        if k.lower() not in (b"content-length", b"content-type")
                    ]
                    new_headers.append((b"content-length", str(len(new_body)).encode()))
                    new_headers.append((b"content-type", b"application/json"))
                    request.scope["headers"] = new_headers

                    async def patched_receive():
                        return {"type": "http.request", "body": new_body, "more_body": False}

                    request = Request(scope=request.scope, receive=patched_receive)
            except Exception as e:
                print(f"[MLE] POST decryption failed: {e}")

        # ── CALL THE ACTUAL ROUTE ─────────────────────────────────────────────
        response = await call_next(request)

        # ── ENCRYPT OUTGOING RESPONSE ─────────────────────────────────────────
        try:
            response_body = b""
            async for chunk in response.body_iterator:
                response_body += chunk

            response_data = json.loads(response_body)
            encrypted_response = mle_handler.encrypt_for_client(response_data, client_public_key)

            new_response_body = json.dumps({"secure_response": encrypted_response}).encode("utf-8")

            return Response(
                content=new_response_body,
                status_code=response.status_code,
                media_type="application/json"
            )
        except Exception as e:
            print(f"[MLE] Response encryption failed: {e}")
            return Response(
                content=response_body,
                status_code=response.status_code,
                media_type="application/json"
            )
