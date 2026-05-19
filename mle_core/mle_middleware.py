import json
import urllib.parse
from starlette.requests import Request
from . import mle_handler

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
            print(f"[MLE] Key resolver failed: {e}")
            client_public_key = None

        if not client_public_key:
            await self.app(scope, receive, send)
            return

        # ── 1. DECRYPT INCOMING GET REQUEST ──
        if scope["method"] == "GET" and "encrypted_data" in request.query_params:
            encrypted_data = request.query_params["encrypted_data"]
            try:
                decrypted = mle_handler.decrypt_from_client(encrypted_data, client_public_key)
                if isinstance(decrypted, dict):
                    new_qs = urllib.parse.urlencode(decrypted)
                    scope["query_string"] = new_qs.encode("utf-8")
            except Exception as e:
                print(f"[MLE] GET decryption failed: {e}")

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

        # ── 3. DECRYPT INCOMING POST REQUEST ──
        if scope["method"] == "POST":
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
                encrypted_data = body_dict.get("encrypted_data")
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
                print(err_msg)
                try:
                    with open("logs/error.log", "a") as f:
                        f.write(f"\n{err_msg}\n")
                except Exception:
                    pass

                await send({
                    "type": "http.response.start",
                    "status": 400,
                    "headers": [(b"content-type", b"application/json")]
                })
                await send({
                    "type": "http.response.body",
                    "body": json.dumps({"status": "error", "detail": f"Decryption failed: {str(e)}"}).encode("utf-8"),
                    "more_body": False
                })
                return

            body_sent = False
            async def custom_receive():
                nonlocal body_sent
                if body_sent:
                    return {"type": "http.disconnect"}
                body_sent = True
                return {
                    "type": "http.request",
                    "body": decrypted_body,
                    "more_body": False
                }

            await self.app(scope, custom_receive, custom_send)
        else:
            # For GET and other non-POST requests, pass down the custom_send channel
            await self.app(scope, receive, custom_send)

 