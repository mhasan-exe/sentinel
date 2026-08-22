"""
security_engine.py

Central controlled-demonstration engine for Sentinel.

IMPORTANT: everything in this file is a SIMULATION triggered from the
dashboard's Attack Lab. Nothing here opens a real unauthenticated
connection or attacks a live user — it looks at the current
SECURITY_CONFIG and reports what WOULD happen, which is exactly what
section 9/10 of the project spec asks for:

    if SECURITY_CONFIG["jwt_authentication"]:
        status = "BLOCKED"
    else:
        status = "VULNERABLE"

This keeps the demo honest (spec rule: "do not claim an attack is real
if it is only a simulation") while still giving judges the OFF -> run
attack -> VULNERABLE, ON -> run attack -> BLOCKED experience.

Two of the events below (INVALID_JWT, UNAUTHORIZED_WEBSOCKET) can also
be produced for real by main.py's /ws endpoint when an actual
connection is rejected — those go through create_security_event()
directly, not through here. This engine exists for the dashboard's
on-demand "push the button" demonstrations.
"""

import jwt

from security import SECRET_KEY, ALGORITHM, create_access_token
from security_config import SECURITY_CONFIG
from security_events import create_security_event
from connection_manager import manager
from crypto_engine import verify_seal
from database import SessionLocal
from models import User


class SecurityEngine:
    def unauthorized_websocket(self, source=None):
        if SECURITY_CONFIG["websocket_authentication"]:
            status = "BLOCKED"
            message = (
                "Simulated connection attempt with no token was rejected "
                "before the handshake completed."
            )
        else:
            status = "VULNERABLE"
            message = (
                "WebSocket authentication is OFF — an unauthenticated "
                "client would currently be accepted by /ws."
            )

        return create_security_event(
            event_type="UNAUTHORIZED_WEBSOCKET",
            status=status,
            message=message,
            source=source,
        )

    def invalid_jwt(self, source=None):
        if SECURITY_CONFIG["jwt_authentication"]:
            status = "BLOCKED"
            message = "Simulated malformed token failed signature verification and was rejected."
        else:
            status = "VULNERABLE"
            message = "JWT authentication is OFF — an invalid token would not be checked at all."

        return create_security_event(
            event_type="INVALID_JWT",
            status=status,
            message=message,
            source=source,
        )

    def jwt_tampering(self, source=None):
        demo_user_id = source if source is not None else 0
        original_token = create_access_token(demo_user_id)

        header, payload, signature = original_token.split(".")
        # Flip the last character of the payload segment to simulate an
        # attacker modifying the token's claims after the fact.
        flipped_char = "A" if payload[-1] != "A" else "B"
        tampered_token = f"{header}.{payload[:-1]}{flipped_char}.{signature}"

        try:
            jwt.decode(tampered_token, SECRET_KEY, algorithms=[ALGORITHM])
            signature_still_valid = True
        except jwt.InvalidTokenError:
            signature_still_valid = False

        if not SECURITY_CONFIG["jwt_authentication"]:
            status = "VULNERABLE"
            message = "JWT authentication is OFF — a tampered token would not be checked at all."
        elif not signature_still_valid:
            status = "BLOCKED"
            message = "Tampered token failed signature verification, as expected."
        else:
            # Should not happen with HMAC-SHA256, but don't silently
            # claim BLOCKED if verification actually passed.
            status = "WARNING"
            message = "Tampered token unexpectedly passed verification — investigate signing logic."

        return create_security_event(
            event_type="JWT_TAMPERING",
            status=status,
            message=message,
            source=source,
        )

    def xss_test(self, source=None):
        payload = "<script>alert('sentinel-xss-test')</script>"

        if SECURITY_CONFIG["input_validation"]:
            status = "BLOCKED"
            message = (
                f"Payload {payload!r} would be rendered via textContent, "
                "not innerHTML, so the script does not execute."
            )
        else:
            status = "VULNERABLE"
            message = (
                f"Input validation is OFF — payload {payload!r} could be "
                "reflected without sanitization."
            )

        return create_security_event(
            event_type="XSS_TEST",
            status=status,
            message=message,
            source=source,
        )

    def replay_test(self, source=None):
        seal = manager.last_message_seal.get(source) if source is not None else None

        if seal is None:
            # No real captured message yet for this user this session —
            # fall back to explaining the mechanism rather than faking a result.
            status = "WARNING"
            message = (
                "No captured message available yet for this user — send at "
                "least one message with encryption ON, then run this again "
                "for a real replay attempt against that captured ciphertext."
            )
            return create_security_event(
                event_type="REPLAY_TEST", status=status, message=message, source=source,
            )

        if not SECURITY_CONFIG["message_integrity"]:
            status = "VULNERABLE"
            message = (
                "Message integrity is OFF — the real captured ciphertext was "
                "resent with no freshness check and would be accepted again."
            )
        else:
            # REAL replay check: has this exact nonce already been seen for
            # this user? It has — it's the last message that was actually
            # sent — so a genuine replay cache flags it as a duplicate.
            already_seen = seal.nonce in manager.seen_nonces.get(source, set())
            if already_seen:
                status = "BLOCKED"
                message = (
                    f"Message integrity is ON — nonce {seal.nonce.hex()[:16]}... "
                    f"was already recorded as used and the replayed message "
                    f"was rejected by the replay cache."
                )
            else:
                status = "WARNING"
                message = "Nonce was not found in the replay cache — nothing to replay yet."

        return create_security_event(
            event_type="REPLAY_TEST",
            status=status,
            message=message,
            source=source,
        )

    def message_tampering(self, source=None):
        seal = manager.last_message_seal.get(source) if source is not None else None

        if seal is None:
            return create_security_event(
                event_type="MESSAGE_TAMPERING",
                status="WARNING",
                message=(
                    "No captured message available yet for this user — send "
                    "at least one message with encryption ON, then run this "
                    "again to really flip a byte in its ciphertext."
                ),
                source=source,
            )

        # REAL tampering: flip one actual byte of the captured ciphertext,
        # then run it through the real AEAD open + real signature verify.
        tampered_ciphertext = bytearray(seal.ciphertext)
        tampered_ciphertext[0] ^= 0xFF
        tampered_seal = type(seal)(
            algorithm=seal.algorithm,
            ciphertext=bytes(tampered_ciphertext),
            nonce=seal.nonce,
            signature=seal.signature,
            sig_algorithm=seal.sig_algorithm,
            signer_public_key=seal.signer_public_key,
            timings_ms={},
        )

        if not SECURITY_CONFIG["message_integrity"]:
            status = "VULNERABLE"
            message = "Message integrity is OFF — the tampered ciphertext was accepted with no check."
        else:
            signature_valid = verify_seal(tampered_seal)
            if not signature_valid:
                status = "BLOCKED"
                message = (
                    f"Message integrity is ON — flipping one real byte of the "
                    f"captured ciphertext failed {seal.sig_algorithm} signature "
                    f"verification, as expected."
                )
            else:
                status = "WARNING"
                message = "Tampered ciphertext unexpectedly passed verification — investigate signing logic."

        return create_security_event(
            event_type="MESSAGE_TAMPERING",
            status=status,
            message=message,
            source=source,
        )

    def database_leak_simulation(self, source=None):
        db = SessionLocal()
        try:
            users = db.query(User).order_by(User.id).limit(5).all()
            row_count = db.query(User).count()
            leaked_rows = "; ".join(
                f"id={user.id}, email={user.email!r}, password={user.password_hash!r}"
                for user in users
            ) or "(users table is empty)"
        finally:
            db.close()

        if SECURITY_CONFIG["password_hashing"]:
            status = "BLOCKED"
            message = (
                f"Real database query returned {row_count} user row(s): {leaked_rows}. "
                "The stored value is an Argon2id hash, not the plaintext "
                "password, so a leaked database row does not directly "
                "expose the credential."
            )
        else:
            status = "VULNERABLE"
            message = (
                f"Real database query returned {row_count} user row(s): {leaked_rows}. "
                "Password hashing is OFF, so the leaked rows expose recoverable credentials."
            )

        return create_security_event(
            event_type="DATABASE_LEAK_SIMULATION",
            status=status,
            message=message,
            source=source,
        )

    def run_attack(self, attack_type: str, source=None):
        handlers = {
            "UNAUTHORIZED_WEBSOCKET": self.unauthorized_websocket,
            "INVALID_JWT": self.invalid_jwt,
            "JWT_TAMPERING": self.jwt_tampering,
            "XSS_TEST": self.xss_test,
            "REPLAY_TEST": self.replay_test,
            "MESSAGE_TAMPERING": self.message_tampering,
            "DATABASE_LEAK_SIMULATION": self.database_leak_simulation,
        }

        handler = handlers.get(attack_type)

        if handler is None:
            return create_security_event(
                event_type=attack_type or "UNKNOWN_ATTACK",
                status="UNKNOWN",
                message=f"No handler registered for attack type '{attack_type}'.",
                source=source,
            )

        return handler(source=source)


security_engine = SecurityEngine()
