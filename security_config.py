import json
from pathlib import Path


_DEFAULT_SECURITY_CONFIG = {
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
    # When ON, every chat message sent through /ws is held in
    # manager.pending_interceptions instead of being delivered
    # immediately — the attacker (Hacker View) must PAUSE/RELEASE/
    # DROP/MODIFY it. Spec section 4's INTERCEPT capability.
    "interception_enabled": False,
}

_CONFIG_PATH = Path(__file__).with_name(".security_config.json")


def _load_security_config():
    config = dict(_DEFAULT_SECURITY_CONFIG)
    try:
        saved = json.loads(_CONFIG_PATH.read_text(encoding="utf-8"))
        for key in config:
            if isinstance(saved.get(key), bool):
                config[key] = saved[key]
    except (OSError, json.JSONDecodeError):
        pass
    return config


def save_security_config(config):
    _CONFIG_PATH.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")


SECURITY_CONFIG = _load_security_config()