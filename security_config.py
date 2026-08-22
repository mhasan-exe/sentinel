import json
from pathlib import Path

from database import SessionLocal
from models import SecuritySetting


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
    try:
        db = SessionLocal()
        try:
            for key, value in config.items():
                setting = db.get(SecuritySetting, key)
                if setting is None:
                    db.add(SecuritySetting(key=key, value=bool(value)))
                else:
                    setting.value = bool(value)
            db.commit()
        finally:
            db.close()
        return
    except Exception:
        # Local SQLite may be unavailable before metadata is created. The
        # file fallback is never required for Vercel's database-backed path.
        try:
            _CONFIG_PATH.write_text(
                json.dumps(config, indent=2) + "\n", encoding="utf-8"
            )
        except OSError:
            pass


def load_database_security_config():
    try:
        db = SessionLocal()
        try:
            settings = db.query(SecuritySetting).all()
            return {setting.key: setting.value for setting in settings}
        finally:
            db.close()
    except Exception:
        return {}


def reload_security_config():
    SECURITY_CONFIG.update(load_database_security_config())


def reset_security_config():
    SECURITY_CONFIG.clear()
    SECURITY_CONFIG.update(_DEFAULT_SECURITY_CONFIG)
    save_security_config(SECURITY_CONFIG)


SECURITY_CONFIG = _load_security_config()
reload_security_config()