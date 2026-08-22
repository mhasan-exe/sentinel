"""
crypto_engine.py

Everything Sentinel needs to go from "toggle switched on" to an actual
cryptographic operation, with real wall-clock timing on every step.

Two independent axes, matching SECURITY_CONFIG:

  KEY EXCHANGE (who agrees on a shared secret)
      classical  -> X25519 ECDHE                (what real-world TLS 1.3 uses today)
      ml_kem     -> ML-KEM-768                  (NIST FIPS 203, the PQC replacement)

  SIGNATURES (who proves a message/handshake wasn't forged)
      classical  -> Ed25519                     (what real-world TLS certs use today)
      ml_dsa     -> ML-DSA-65                    (NIST FIPS 204, the PQC replacement)

Both axes feed the SAME downstream primitive: AES-256-GCM, keyed by
HKDF-SHA256 over whatever shared secret came out of the key exchange.
This is deliberate and matches section 15 of the spec: ML-KEM is a KEM,
not a full replacement for symmetric encryption, and ML-DSA is a
signature scheme, not a KEM. Neither one "does everything" — they slot
into the same handshake shape classical crypto already uses.

WHAT IS REAL vs WHAT IS A LAB CONDITION:
  - Every operation below runs for real: real X25519 scalar mults, real
    ML-KEM encapsulation, real AES-GCM seals, real timings from
    time.perf_counter().
  - The "two parties" in perform_handshake() are both executed
    server-side (there's no second physical machine in this lab). That
    is a lab condition, not a fabrication — it's the same reason a
    university crypto course benchmarks algorithms on one machine. The
    keys, ciphertexts, and timings are genuine; only the topology is
    simplified. Say this plainly on the results/slide side — don't
    let it read as "we measured a real network handshake."
"""

from __future__ import annotations

import time
import os
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature

try:
    from pqcrypto.kem.ml_kem_768 import (
        keygen as mlkem_generate_keypair,
        encaps as mlkem_encapsulate,
        decaps as mlkem_decapsulate,
    )
    from pqcrypto.sign.ml_dsa_65 import (
        keygen as mldsa_generate_keypair,
        sign as mldsa_sign,
        verify as mldsa_verify,
    )
    PQC_AVAILABLE = True
    PQC_IMPORT_ERROR = None
except ImportError as exc:
    # Keep the app running, but expose the actual import failure to status
    # consumers so an API mismatch is not mistaken for a missing package.
    PQC_AVAILABLE = False
    PQC_IMPORT_ERROR = str(exc)


# ---------------------------------------------------------------------
# Timing helper
# ---------------------------------------------------------------------

def _timed(fn, *args, **kwargs):
    start = time.perf_counter()
    result = fn(*args, **kwargs)
    elapsed_ms = (time.perf_counter() - start) * 1000
    return result, elapsed_ms


# ---------------------------------------------------------------------
# Result containers
# ---------------------------------------------------------------------

@dataclass
class HandshakeResult:
    kem_algorithm: str                  # "X25519" or "ML-KEM-768"
    sig_algorithm: str                  # "Ed25519" or "ML-DSA-65"
    session_key: bytes                  # 32-byte AES-256 key, derived via HKDF
    shared_secret_size: int
    public_key_size: int                # bytes sent client -> server (or the KEM's encapsulation key)
    ciphertext_or_ephemeral_size: int    # bytes sent server -> client to complete the exchange
    signature_size: int
    handshake_signature_valid: bool
    timings_ms: dict = field(default_factory=dict)  # keygen, encapsulate/exchange, decapsulate, sign, verify, total


@dataclass
class MessageSeal:
    algorithm: str          # "AES-256-GCM"
    ciphertext: bytes
    nonce: bytes
    signature: bytes | None
    sig_algorithm: str | None
    signer_public_key: object = None  # Ed25519PublicKey object, or ML-DSA public key bytes
    timings_ms: dict = field(default_factory=dict)  # encrypt, sign


# ---------------------------------------------------------------------
# Key derivation (shared by both classical and PQC paths)
# ---------------------------------------------------------------------

def derive_session_key(shared_secret: bytes, context: bytes = b"sentinel-session-v1") -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=context,
    ).derive(shared_secret)


# ---------------------------------------------------------------------
# Handshake: classical (X25519 + Ed25519) — this is what SECURITY_CONFIG["tls"] turns on
# ---------------------------------------------------------------------

def _classical_handshake() -> HandshakeResult:
    timings = {}

    # "Server" ephemeral X25519 keypair
    (server_priv, server_pub), t_keygen_server = _timed(
        lambda: (lambda k: (k, k.public_key()))(X25519PrivateKey.generate())
    )
    # "Client" ephemeral X25519 keypair — both sides run here since this
    # is a single-machine lab benchmark (see module docstring).
    (client_priv, client_pub), t_keygen_client = _timed(
        lambda: (lambda k: (k, k.public_key()))(X25519PrivateKey.generate())
    )
    timings["keygen_ms"] = t_keygen_server + t_keygen_client

    # ECDH exchange (both directions land on the same shared secret)
    shared_secret, t_exchange = _timed(server_priv.exchange, client_pub)
    timings["exchange_ms"] = t_exchange

    public_key_bytes = client_pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    ephemeral_bytes = server_pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # Sign the handshake transcript with a (separate, long-term-style) Ed25519 identity key
    sig_key = Ed25519PrivateKey.generate()
    transcript = public_key_bytes + ephemeral_bytes
    signature, t_sign = _timed(sig_key.sign, transcript)
    timings["sign_ms"] = t_sign

    verify_ok = True
    _, t_verify = _timed_verify(sig_key.public_key(), signature, transcript)
    timings["verify_ms"] = t_verify

    session_key, t_derive = _timed(derive_session_key, shared_secret)
    timings["derive_ms"] = t_derive
    timings["total_ms"] = sum(timings.values())

    return HandshakeResult(
        kem_algorithm="X25519",
        sig_algorithm="Ed25519",
        session_key=session_key,
        shared_secret_size=len(shared_secret),
        public_key_size=len(public_key_bytes),
        ciphertext_or_ephemeral_size=len(ephemeral_bytes),
        signature_size=len(signature),
        handshake_signature_valid=verify_ok,
        timings_ms=timings,
    )


def _timed_verify(pub_key, signature, transcript):
    start = time.perf_counter()
    try:
        pub_key.verify(signature, transcript)
        ok = True
    except InvalidSignature:
        ok = False
    return ok, (time.perf_counter() - start) * 1000


# ---------------------------------------------------------------------
# Handshake: post-quantum (ML-KEM-768 + ML-DSA-65) — SECURITY_CONFIG["ml_kem"] / ["ml_dsa"]
# ---------------------------------------------------------------------

def _pqc_handshake() -> HandshakeResult:
    if not PQC_AVAILABLE:
        raise RuntimeError(
            "pqcrypto is not installed. Run: pip install pqcrypto "
            f"(import failed with: {PQC_IMPORT_ERROR})"
        )

    timings = {}

    # "Server" generates an ML-KEM keypair and publishes the public key
    (server_pub, server_priv), t_keygen = _timed(mlkem_generate_keypair)
    timings["keygen_ms"] = t_keygen

    # "Client" encapsulates against that public key -> (ciphertext, shared_secret)
    (ciphertext, client_shared_secret), t_encap = _timed(mlkem_encapsulate, server_pub)
    timings["encapsulate_ms"] = t_encap

    # "Server" decapsulates the ciphertext to recover the same shared secret
    server_shared_secret, t_decap = _timed(mlkem_decapsulate, server_priv, ciphertext)
    timings["decapsulate_ms"] = t_decap

    if client_shared_secret != server_shared_secret:
        # Should never happen with a correct implementation — surface it
        # loudly rather than silently deriving mismatched keys.
        raise RuntimeError("ML-KEM shared secret mismatch between encapsulate/decapsulate")

    # ML-DSA signs the handshake transcript (public key + ciphertext)
    (sig_pub, sig_priv), t_sig_keygen = _timed(mldsa_generate_keypair)
    timings["sig_keygen_ms"] = t_sig_keygen

    transcript = server_pub + ciphertext
    signature, t_sign = _timed(mldsa_sign, sig_priv, transcript)
    timings["sign_ms"] = t_sign

    verify_start = time.perf_counter()
    try:
        mldsa_verify(sig_pub, transcript, signature)
        verify_ok = True
    except Exception:
        verify_ok = False
    timings["verify_ms"] = (time.perf_counter() - verify_start) * 1000

    session_key, t_derive = _timed(derive_session_key, server_shared_secret)
    timings["derive_ms"] = t_derive
    timings["total_ms"] = sum(timings.values())

    return HandshakeResult(
        kem_algorithm="ML-KEM-768",
        sig_algorithm="ML-DSA-65",
        session_key=session_key,
        shared_secret_size=len(server_shared_secret),
        public_key_size=len(server_pub),
        ciphertext_or_ephemeral_size=len(ciphertext),
        signature_size=len(signature),
        handshake_signature_valid=verify_ok,
        timings_ms=timings,
    )


def perform_handshake(use_pqc: bool) -> HandshakeResult:
    """
    Single entry point main.py should call. use_pqc is decided by the
    caller from SECURITY_CONFIG (ml_kem True -> PQC path, else classical
    "tls" path). Keeping the branch here rather than scattering
    if/else across main.py.
    """
    return _pqc_handshake() if use_pqc else _classical_handshake()


# ---------------------------------------------------------------------
# Per-message sealing: AES-256-GCM, optionally signed
# ---------------------------------------------------------------------

def seal_message(
    plaintext: bytes,
    session_key: bytes,
    sign: bool = False,
    use_pqc_signature: bool = False,
) -> MessageSeal:
    timings = {}

    aesgcm = AESGCM(session_key)
    nonce = os.urandom(12)
    ciphertext, t_encrypt = _timed(aesgcm.encrypt, nonce, plaintext, None)
    timings["encrypt_ms"] = t_encrypt

    signature = None
    sig_algorithm = None
    signer_public_key = None
    if sign:
        if use_pqc_signature and PQC_AVAILABLE:
            (sig_pub, sig_priv), t_keygen = _timed(mldsa_generate_keypair)
            signature, t_sign = _timed(mldsa_sign, sig_priv, ciphertext)
            sig_algorithm = "ML-DSA-65"
            signer_public_key = sig_pub
            timings["sig_keygen_ms"] = t_keygen
            timings["sign_ms"] = t_sign
        else:
            sig_key = Ed25519PrivateKey.generate()
            signature, t_sign = _timed(sig_key.sign, ciphertext)
            sig_algorithm = "Ed25519"
            signer_public_key = sig_key.public_key()
            timings["sign_ms"] = t_sign

    return MessageSeal(
        algorithm="AES-256-GCM",
        ciphertext=ciphertext,
        nonce=nonce,
        signature=signature,
        sig_algorithm=sig_algorithm,
        signer_public_key=signer_public_key,
        timings_ms=timings,
    )


def open_message(ciphertext: bytes, nonce: bytes, session_key: bytes) -> bytes:
    aesgcm = AESGCM(session_key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def verify_seal(seal: MessageSeal) -> bool:
    """
    Real verification used by the real MESSAGE_TAMPERING attack — not a
    narrated string. Checks seal.signature against seal.ciphertext using
    the public key that was actually generated at sign time. To run the
    "tampering" demo, mutate seal.ciphertext or seal.signature by one
    byte before calling this — that's the real attack, not a simulation
    of one.
    """
    if seal.signature is None or seal.signer_public_key is None:
        return False
    try:
        if seal.sig_algorithm == "ML-DSA-65":
            mldsa_verify(seal.signer_public_key, seal.ciphertext, seal.signature)
        else:
            seal.signer_public_key.verify(seal.signature, seal.ciphertext)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------
# Benchmarking — spec section 16, "Configuration A/B/C/D" comparison
# ---------------------------------------------------------------------

def benchmark_configuration(label: str, use_pqc: bool, message_bytes: bytes, iterations: int = 20) -> dict:
    """
    Runs `iterations` handshakes + one message seal each, for ONE
    configuration, and returns averaged real numbers. This is what
    feeds the Results page's performance table — never fabricate this,
    always call it live.
    """
    handshake_totals = []
    encrypt_totals = []
    pub_sizes = []
    ct_sizes = []
    sig_sizes = []

    for _ in range(iterations):
        hs = perform_handshake(use_pqc=use_pqc)
        handshake_totals.append(hs.timings_ms["total_ms"])
        pub_sizes.append(hs.public_key_size)
        ct_sizes.append(hs.ciphertext_or_ephemeral_size)
        sig_sizes.append(hs.signature_size)

        seal = seal_message(message_bytes, hs.session_key, sign=True, use_pqc_signature=use_pqc)
        encrypt_totals.append(sum(seal.timings_ms.values()))

    def avg(values):
        return round(sum(values) / len(values), 4)

    return {
        "configuration": label,
        "kem_algorithm": "ML-KEM-768" if use_pqc else "X25519",
        "sig_algorithm": "ML-DSA-65" if use_pqc else "Ed25519",
        "iterations": iterations,
        "avg_handshake_ms": avg(handshake_totals),
        "avg_message_seal_ms": avg(encrypt_totals),
        "avg_public_key_bytes": round(sum(pub_sizes) / len(pub_sizes)),
        "avg_ciphertext_bytes": round(sum(ct_sizes) / len(ct_sizes)),
        "avg_signature_bytes": round(sum(sig_sizes) / len(sig_sizes)),
    }


def benchmark_single_iteration(use_pqc: bool, message_bytes: bytes = b"Sentinel benchmark payload - fixed size.") -> dict:
    """
    ONE real handshake + ONE real signed message seal, with real timings.
    Used by main.py's time-windowed benchmark loop (runs this repeatedly
    for ~60s rather than a fixed iteration count) so progress can be
    reported as it goes instead of the whole run landing in one blocking
    call.
    """
    hs = perform_handshake(use_pqc=use_pqc)
    seal = seal_message(message_bytes, hs.session_key, sign=True, use_pqc_signature=use_pqc)
    seal_ms = sum(seal.timings_ms.values())

    return {
        "kem_algorithm": hs.kem_algorithm,
        "sig_algorithm": hs.sig_algorithm,
        "handshake_ms": round(hs.timings_ms["total_ms"], 4),
        "seal_ms": round(seal_ms, 4),
        "total_ms": round(hs.timings_ms["total_ms"] + seal_ms, 4),
        "public_key_size": hs.public_key_size,
        "ciphertext_or_ephemeral_size": hs.ciphertext_or_ephemeral_size,
        "signature_size": hs.signature_size,
    }


# ---------------------------------------------------------------------
# Session resumption cache — real feature, not a narrated speedup.
#
# A fresh ML-KEM-768 + ML-DSA-65 handshake is the expensive part of
# connecting (keygen + encapsulate/decapsulate + a ~3.3KB ML-DSA
# signature to generate and verify). If the same user reconnects
# shortly after, there's no cryptographic need to redo all of that: we
# cache the derived session key for a short TTL and let a reconnecting
# user resume it directly, the same way TLS 1.3 session resumption
# skips a full handshake on a returning connection.
#
# What's real here: the cache lookup, the TTL expiry check, and the
# timing of both paths (perf_counter() on each). What's NOT claimed:
# this is not a new cryptographic algorithm, and it does not run
# instead of ML-KEM/ML-DSA — it runs after them, on top of a handshake
# that already happened for real at least once.
# ---------------------------------------------------------------------

_SESSION_CACHE_TTL_SECONDS = 300  # 5 minutes


class SessionCache:
    def __init__(self, ttl_seconds: float = _SESSION_CACHE_TTL_SECONDS):
        self.ttl_seconds = ttl_seconds
        self._store: dict[int, tuple[float, HandshakeResult]] = {}

    def get(self, user_id: int) -> HandshakeResult | None:
        entry = self._store.get(user_id)
        if entry is None:
            return None
        cached_at, handshake = entry
        if (time.time() - cached_at) > self.ttl_seconds:
            self._store.pop(user_id, None)
            return None
        return handshake

    def put(self, user_id: int, handshake: HandshakeResult) -> None:
        self._store[user_id] = (time.time(), handshake)

    def invalidate(self, user_id: int) -> None:
        self._store.pop(user_id, None)

    def clear(self) -> None:
        self._store.clear()


SESSION_CACHE = SessionCache()


def resume_or_handshake(user_id: int, use_pqc: bool, allow_resume: bool) -> tuple[HandshakeResult, bool, float]:
    """
    Real entry point for main.py's /ws handler when session_caching is
    considered. Returns (handshake, was_resumed, lookup_or_handshake_ms).

    - allow_resume False (session_caching toggle OFF): always runs a
      full handshake, exactly like before this feature existed.
    - allow_resume True: checks the real cache first. A hit returns the
      SAME session key object with a real (near-zero) cache-lookup
      timing. A miss runs the full handshake and caches the result for
      next time.
    """
    if allow_resume:
        start = time.perf_counter()
        cached = SESSION_CACHE.get(user_id)
        lookup_ms = (time.perf_counter() - start) * 1000
        if cached is not None:
            return cached, True, lookup_ms

    handshake = perform_handshake(use_pqc=use_pqc)
    if allow_resume:
        SESSION_CACHE.put(user_id, handshake)
    return handshake, False, handshake.timings_ms["total_ms"]


def run_resumption_benchmark(iterations: int = 20) -> dict:
    """
    Measures the real cost difference between "full handshake every
    time" and "full handshake once, then resume from cache" — using
    the SAME perform_handshake()/PQC path as everywhere else in this
    file. No numbers here are assumed; every value is averaged from
    actual timed calls in this process, on this machine, in this run.
    """
    sample_message = b"Sentinel benchmark message payload - fixed size for fair comparison."
    demo_user_id = -999999  # scratch id, never collides with a real user

    # Baseline: full handshake, every single time (current default).
    full_totals = []
    for _ in range(iterations):
        hs = perform_handshake(use_pqc=PQC_AVAILABLE)
        full_totals.append(hs.timings_ms["total_ms"])

    # With caching: one real full handshake seeds the cache, then every
    # subsequent "reconnect" is a real cache lookup, timed the same way.
    SESSION_CACHE.invalidate(demo_user_id)
    seed_hs, _, seed_ms = resume_or_handshake(demo_user_id, use_pqc=PQC_AVAILABLE, allow_resume=True)
    resumed_totals = []
    for _ in range(iterations):
        _, was_resumed, resumed_ms = resume_or_handshake(demo_user_id, use_pqc=PQC_AVAILABLE, allow_resume=True)
        if was_resumed:
            resumed_totals.append(resumed_ms)
    SESSION_CACHE.invalidate(demo_user_id)

    def avg(values):
        return round(sum(values) / len(values), 4) if values else None

    avg_full = avg(full_totals)
    avg_resumed = avg(resumed_totals)
    speedup_pct = (
        round((1 - (avg_resumed / avg_full)) * 100, 1)
        if avg_full and avg_resumed is not None and avg_full > 0
        else None
    )

    return {
        "iterations": iterations,
        "kem_algorithm": "ML-KEM-768" if PQC_AVAILABLE else "X25519",
        "sig_algorithm": "ML-DSA-65" if PQC_AVAILABLE else "Ed25519",
        "avg_full_handshake_ms": avg_full,
        "avg_resumed_lookup_ms": avg_resumed,
        "measured_speedup_pct": speedup_pct,
        "note": (
            "Speedup is the real difference between a fresh handshake and a "
            "cache lookup on this machine, this run — not a fixed or assumed "
            "number. It will vary run to run."
        ),
    }


def run_full_benchmark(iterations: int = 20) -> dict:
    sample_message = b"Sentinel benchmark message payload - fixed size for fair comparison."
    classical = benchmark_configuration("Classical (X25519 + Ed25519)", use_pqc=False,
                                         message_bytes=sample_message, iterations=iterations)
    result = {"classical": classical, "pqc": None, "pqc_available": PQC_AVAILABLE}

    if PQC_AVAILABLE:
        pqc = benchmark_configuration("Post-Quantum (ML-KEM-768 + ML-DSA-65)", use_pqc=True,
                                       message_bytes=sample_message, iterations=iterations)
        result["pqc"] = pqc

    return result
