SECURITY_CONFIG = {
    "password_hashing": True,
    "jwt_authentication": True,
    "websocket_authentication": True,
    "input_validation": True,
    "message_integrity": False,
    "encryption": False,
    "tls": False,
    "ml_kem": False,
    "ml_dsa": False,
    # When ON, a returning user's /ws connection can resume a still-valid
    # cached session key instead of re-running the full asymmetric
    # handshake. Real feature, real measured speedup — see
    # crypto_engine.py's SessionCache and run_resumption_benchmark().
    "session_caching": False,
}