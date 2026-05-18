from .mle_handler import (
    MLEHandler, 
    encrypt_for_client, 
    decrypt_from_client, 
    encrypt_internal, 
    decrypt_internal,
    SERVER_PUBLIC_KEY
)
from .mle_middleware import MLEMiddleware


def init(private_key: str = None, public_key: str = None, private_key_path: str = None, public_key_path: str = None, algorithm: str = "RS256"):
    """
    Optional manual initializer to override the automatic key detection.
    """
    from . import mle_handler
    if private_key_path and public_key_path:
        handler = MLEHandler.from_files(private_key_path, public_key_path, algorithm)
    elif private_key and public_key:
        handler = MLEHandler(private_key, public_key, algorithm)
    else:
        # Fallback to automatic detection
        return mle_handler._mle_instance
    
    mle_handler._mle_instance = handler
    return handler
