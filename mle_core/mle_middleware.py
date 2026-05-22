import json
import urllib.parse
import os
from starlette.requests import Request
from . import mle_handler
import logging

logger = logging.getLogger("mle_middleware")


class MLEMiddleware:
    def __init__(self, app, key_resolver):
        self.app = app
        self.key_resolver = key_resolver

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)
        try:
            client_public_key = await self.key_resolver(request)
        except Exception as e:
            logger.debug(f"[MLE] Key resolver failed: {e}")
            client_public_key = None

        method = scope["method"]
        is_encrypted = False
        body_bytes = None

        # ── Detect encryption ──
        if method == "GET":
            is_encrypted = "encrypted_data" in request.query_params or "encrypted_payload" in request.query_params
        elif method in ("POST", "PUT", "PATCH"):
            body_chunks = []
            while True:
                message = await receive()
                if message["type"] == "http.request":
                    body_chunks.append(message.get("body", b""))
                    if not message.get("more_body", False):
                        break
                elif message["type"] == "http.disconnect":
                    return
            body_bytes = b"".join(body_chunks)

        # Silent detection for POST/PUT/PATCH bodies
        if body_bytes:
            try:
                body_dict = json.loads(body_bytes)
                is_encrypted = ("encrypted_data" in body_dict) or ("encrypted_payload" in body_dict)
                logger.debug(f"[MLE] Detected encrypted payload: {is_encrypted}")
            except Exception:
                pass

        original_receive = receive
        if body_bytes is not None:
            body_sent = False
            async def custom_receive():
                nonlocal body_sent
                if body_sent:
                    # Block and wait for the real disconnect event
                    return await original_receive()
                body_sent = True
                return {
                    "type": "http.request",
                    "body": body_bytes,
                    "more_body": False
                }
            receive = custom_receive

        # ──────────────────────────────────────────────
        # Server MLE flag
        # ──────────────────────────────────────────────
        mle_enabled = os.getenv("MLE_ENABLED", "True").lower() in ("true", "1", "yes")

        # ──────────────────────────────────────────────
        # Decision matrix (6 cases)
        # ──────────────────────────────────────────────

        # Case 1: MLE disabled + plain request → bypass
        # Case 2: MLE disabled + encrypted request → 400 error
        if not mle_enabled:
            if is_encrypted:
                from starlette.responses import JSONResponse
                response = JSONResponse(
                    status_code=400,
                    content={"status": "error", "detail": "MLE is disabled but encrypted payload received"},
                )
                await response(scope, receive, send)
                return
            # Plain request – bypass all MLE processing
            await self.app(scope, receive, send)
            return

        # Case 3: MLE enabled + no client key + encrypted request → 400 error
        # Case 4: MLE enabled + no client key + plain request → bypass
        if client_public_key is None:
            if is_encrypted:
                from starlette.responses import JSONResponse
                response = JSONResponse(
                    status_code=400,
                    content={"status": "error", "detail": "MLE enabled but no client public key"},
                )
                await response(scope, receive, send)
                return
            # No key and plain payload – bypass (client not using MLE yet)
            await self.app(scope, receive, send)
            return

        # Case 5: MLE enabled + client key + plain request → 400 error (if payload exists)
        if not is_encrypted:
            has_data = False
            if method == "GET" and request.query_params:
                has_data = True
            elif method in ("POST", "PUT", "PATCH") and body_bytes:
                has_data = True
                
            if has_data:
                from starlette.responses import JSONResponse
                response = JSONResponse(
                    status_code=400,
                    content={"status": "error", "detail": "MLE enabled but request is not encrypted"},
                )
                await response(scope, receive, send)
                return

        # Case 6: MLE enabled + client key + encrypted request → HAPPY PATH
        # Continue with decryption / encryption logic below
        # ──────────────────────────────────────────────



        # ── 1. DECRYPT INCOMING GET REQUEST ──
        if scope["method"] == "GET" and request.query_params:
            if "encrypted_data" in request.query_params:
                encrypted_data = request.query_params["encrypted_data"]
                try:
                    decrypted = mle_handler.decrypt_from_client(encrypted_data, client_public_key)
                    if isinstance(decrypted, dict):
                        new_qs = urllib.parse.urlencode(decrypted)
                        scope["query_string"] = new_qs.encode("utf-8")
                except Exception as e:
                    logger.debug(f"[MLE] GET decryption failed: {e}")
                    from starlette.responses import JSONResponse
                    response = JSONResponse(
                        status_code=400,
                        content={"status": "error", "detail": f"GET decryption failed: {str(e)}"}
                    )
                    await response(scope, receive, send)
                    return

        # ── 2. PREPARE CUSTOM SEND TO ENCRYPT RESPONSE ──
        response_start_message = None
        response_body_chunks = []

        async def custom_send(message):
            nonlocal response_start_message, response_body_chunks

            if message["type"] == "http.response.start":
                response_start_message = message
                return  # Hold start message to adjust Content-Length later

            elif message["type"] == "http.response.body":
                response_body_chunks.append(message.get("body", b""))
                if message.get("more_body", False):
                    return

                # Full response body collected, let's encrypt it!
                full_body = b"".join(response_body_chunks)
                try:
                    # Debug output removed to avoid logging response bodies
                    response_data = json.loads(full_body)
                    encrypted_response = mle_handler.encrypt_for_client(response_data, client_public_key)
                    new_response_body = encrypted_response.encode("utf-8")

                    if response_start_message:
                        headers = [
                            (k, v) for k, v in response_start_message.get("headers", [])
                            if k.lower() not in (b"content-length", b"content-type")
                        ]
                        headers.append((b"content-length", str(len(new_response_body)).encode("utf-8")))
                        headers.append((b"content-type", b"text/plain"))
                        response_start_message["headers"] = headers
                        await send(response_start_message)

                    await send({
                        "type": "http.response.body",
                        "body": new_response_body,
                        "more_body": False
                    })
                except Exception:
                    # Fallback to original response if JSON loading/encryption fails
                    if response_start_message:
                        await send(response_start_message)
                    await send({
                        "type": "http.response.body",
                        "body": full_body,
                        "more_body": False
                    })

        # ── 3. DECRYPT INCOMING POST/PUT/PATCH REQUEST ──
        if scope["method"] in ("POST", "PUT", "PATCH"):
            body_chunks = []
            while True:
                message = await receive()
                if message["type"] == "http.request":
                    body_chunks.append(message.get("body", b""))
                    if not message.get("more_body", False):
                        break
                elif message["type"] == "http.disconnect":
                    return

            raw_body = b"".join(body_chunks)
            decrypted_body = raw_body

            try:
                body_dict = json.loads(raw_body)
                encrypted_data = body_dict.get("encrypted_data") or body_dict.get("encrypted_payload")
                if encrypted_data:
                    decrypted = mle_handler.decrypt_from_client(encrypted_data, client_public_key)
                    decrypted_body = json.dumps(decrypted).encode("utf-8")

                    # Update scope headers with new decrypted body Content-Length
                    headers = [
                        (k, v) for k, v in scope.get("headers", [])
                        if k.lower() != b"content-length"
                    ]
                    headers.append((b"content-length", str(len(decrypted_body)).encode("utf-8")))
                    scope["headers"] = headers
            except Exception as e:
                import traceback
                err_msg = f"[MLE] POST decryption failed: {e}\n{traceback.format_exc()}"
                logger.debug(err_msg)
                try:
                    with open("logs/error.log", "a") as f:
                        f.write(f"\n{err_msg}\n")
                except Exception:
                    pass

                from starlette.responses import JSONResponse
                response = JSONResponse(
                    status_code=400,
                    content={"status": "error", "detail": f"Decryption failed: {str(e)}"}
                )
                await response(scope, receive, send)
                return

            body_sent = False
            async def custom_receive_post():
                nonlocal body_sent
                if body_sent:
                    return await original_receive()
                body_sent = True
                return {
                    "type": "http.request",
                    "body": decrypted_body,
                    "more_body": False
                }

            await self.app(scope, custom_receive_post, custom_send)
        else:
            # For GET and other non-POST requests, pass down the custom_send channel
            await self.app(scope, receive, custom_send)