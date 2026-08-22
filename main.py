from fastapi import FastAPI, Request, Form, Depends, WebSocket, WebSocketDisconnect
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from sqlalchemy import select
from datetime import datetime, timezone
import itertools
import json
import base64
import asyncio
import uuid
import time

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # python-dotenv is optional — if it's not installed, SENTINEL_SECRET_KEY
    # just has to be set in the real environment instead of a .env file.
    pass

from database import Base, SessionLocal, engine
from models import User, SurveyResponse, ExperimentResult, Message
from security import (
    hash_password,
    verify_password,
    get_current_user,
    get_current_user_optional,
    create_access_token,
    decode_access_token,
    decode_access_token_unverified,
)
from connection_manager import manager
from security_events import create_security_event
from security_config import SECURITY_CONFIG
from security_engine import security_engine
from security_survey import (
    QUESTIONS,
    score_responses,
    build_profile,
)
from crypto_engine import (
    perform_handshake,
    seal_message,
    benchmark_single_iteration,
    resume_or_handshake,
    run_resumption_benchmark,
    SESSION_CACHE,
    PQC_AVAILABLE,
)

app = FastAPI()
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# Create any tables added since the last deployment, including the chat table.
# This is idempotent and works with the Neon DATABASE_URL on Vercel.
Base.metadata.create_all(bind=engine)

# Negative ids so anonymous/unauthenticated demo connections can never
# collide with a real user's positive database id.
_anonymous_id_counter = itertools.count(-1, -1)

# ---------------------------------------------------------------------
# Benchmark session state
#
# A benchmark is a ~60s WINDOW, not a single click. While one is active:
#   - a background loop keeps running real handshake+seal iterations
#     (classical, and PQC if pqcrypto is installed), reporting live
#     progress every couple of seconds
#   - any REAL /ws connection that completes its own real handshake
#     during this window gets tagged with the same session_id, so the
#     session's final numbers include organic chat traffic, not only
#     synthetic loop iterations
#   - any REAL chat message latency report that lands during this
#     window is tagged the same way
#
# Single dict because this is a one-process demo server — fine for a
# researchathon; would need a lock or per-worker state for multiple
# workers.
# ---------------------------------------------------------------------
ACTIVE_BENCHMARK_SESSION = {"id": None, "ends_at": None}


def _current_benchmark_session_id() -> str | None:
    if ACTIVE_BENCHMARK_SESSION["id"] and time.time() < ACTIVE_BENCHMARK_SESSION["ends_at"]:
        return ACTIVE_BENCHMARK_SESSION["id"]
    return None


async def run_benchmark_session(session_id: str, duration_seconds: int):
    """
    Runs for real, wall-clock, for `duration_seconds` (~60s by default).
    Not a fixed iteration count finishing in a blink — the loop keeps
    going, yielding control with asyncio.sleep(0) between iterations so
    real /ws connections aren't starved, until the clock runs out.
    """
    start = time.time()
    end = start + duration_seconds
    next_progress_at = start

    classical_timings = []
    pqc_timings = []

    while time.time() < end:
        db = SessionLocal()
        try:
            classical = benchmark_single_iteration(use_pqc=False)
            classical_timings.append(classical["total_ms"])
            db.add(ExperimentResult(
                experiment_type="HANDSHAKE_BENCHMARK",
                configuration="classical",
                result="MEASURED",
                latency_ms=classical["total_ms"],
                detail_json=json.dumps(classical),
                session_id=session_id,
            ))

            if PQC_AVAILABLE:
                pqc = benchmark_single_iteration(use_pqc=True)
                pqc_timings.append(pqc["total_ms"])
                db.add(ExperimentResult(
                    experiment_type="HANDSHAKE_BENCHMARK",
                    configuration="pqc",
                    result="MEASURED",
                    latency_ms=pqc["total_ms"],
                    detail_json=json.dumps(pqc),
                    session_id=session_id,
                ))

            db.commit()
        finally:
            db.close()

        if time.time() >= next_progress_at:
            elapsed = time.time() - start
            await manager.send_to_dashboards({
                "type": "benchmark_progress",
                "session_id": session_id,
                "elapsed_seconds": round(elapsed, 1),
                "duration_seconds": duration_seconds,
                "classical_iterations": len(classical_timings),
                "pqc_iterations": len(pqc_timings),
                "classical_avg_ms": round(sum(classical_timings) / len(classical_timings), 3) if classical_timings else None,
                "pqc_avg_ms": round(sum(pqc_timings) / len(pqc_timings), 3) if pqc_timings else None,
            })
            next_progress_at = time.time() + 2

        # Yield control so this loop never blocks real /ws traffic —
        # that's what lets a real handshake happen DURING the window.
        await asyncio.sleep(0.05)

    db = SessionLocal()
    try:
        real_handshakes = db.scalars(
            select(ExperimentResult).where(
                ExperimentResult.session_id == session_id,
                ExperimentResult.experiment_type == "HANDSHAKE",
            )
        ).all()
        real_count = len(real_handshakes)
        real_avg = (
            round(sum(r.latency_ms for r in real_handshakes) / real_count, 3)
            if real_count else None
        )

        real_latencies = db.scalars(
            select(ExperimentResult).where(
                ExperimentResult.session_id == session_id,
                ExperimentResult.experiment_type == "MESSAGE_LATENCY",
            )
        ).all()
        latency_by_medium = {}
        for row in real_latencies:
            latency_by_medium.setdefault(row.configuration, []).append(row.latency_ms)
        latency_by_medium = {
            medium: {"count": len(values), "avg_ms": round(sum(values) / len(values), 3)}
            for medium, values in latency_by_medium.items()
        }

        summary = {
            "session_id": session_id,
            "duration_seconds": duration_seconds,
            "classical_iterations": len(classical_timings),
            "classical_avg_ms": round(sum(classical_timings) / len(classical_timings), 3) if classical_timings else None,
            "pqc_iterations": len(pqc_timings),
            "pqc_avg_ms": round(sum(pqc_timings) / len(pqc_timings), 3) if pqc_timings else None,
            "pqc_available": PQC_AVAILABLE,
            "real_ws_handshakes_captured": real_count,
            "real_ws_handshake_avg_ms": real_avg,
            "real_message_latency_by_medium": latency_by_medium,
        }

        db.add(ExperimentResult(
            experiment_type="HANDSHAKE_BENCHMARK_SESSION",
            configuration="session_summary",
            result="MEASURED",
            latency_ms=summary["classical_avg_ms"],
            detail_json=json.dumps(summary),
            session_id=session_id,
        ))
        db.commit()
    finally:
        db.close()

    ACTIVE_BENCHMARK_SESSION["id"] = None
    ACTIVE_BENCHMARK_SESSION["ends_at"] = None

    await manager.send_to_dashboards({
        "type": "benchmark_result",
        "session": summary,
    })


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.get("/")
def homepage(request: Request, user_id: int | None = Depends(get_current_user_optional)):
    return templates.TemplateResponse(
        request,
        "home.html",
        {"user_id": user_id}
    )


@app.get("/presentation")
def presentation_page(request: Request, user_id: int | None = Depends(get_current_user_optional)):
    import glob
    import os

    slide_files = sorted(
        os.path.basename(p)
        for p in glob.glob("static/presentation/slide-*.png")
    )

    return templates.TemplateResponse(
        request,
        "presentation.html",
        {"slide_files": slide_files, "user_id": user_id}
    )


@app.get("/assessment")
def assessment_page(request: Request, user_id: int | None = Depends(get_current_user_optional)):
    return templates.TemplateResponse(
        request,
        "assessment.html",
        {"questions": QUESTIONS, "user_id": user_id}
    )


@app.post("/assessment")
async def assessment_submit(
    request: Request,
    db: Session = Depends(get_db),
):
    form = await request.form()

    raw_answers = {
        question["id"]: form.get(question["id"])
        for question in QUESTIONS
    }

    scored = score_responses(raw_answers)
    profile = build_profile(scored["category_scores"], scored["overall_score"])

    # If the visitor happens to already be logged in, attach the
    # response to their account; otherwise it's stored anonymously.
    user_id = None
    token = request.cookies.get("access_token")
    if token:
        try:
            payload = decode_access_token(token.replace("Bearer ", ""))
            user_id = int(payload["sub"])
        except Exception:
            user_id = None

    response = SurveyResponse(
        user_id=user_id,
        raw_answers_json=json.dumps(raw_answers),
        breakdown_json=json.dumps(scored["breakdown"]),
        category_scores_json=json.dumps(scored["category_scores"]),
        overall_score=scored["overall_score"],
        profile_name=profile["profile_name"],
    )
    db.add(response)
    db.commit()

    return templates.TemplateResponse(
        request,
        "assessment_result.html",
        {"profile": profile, "logged_in": user_id is not None, "user_id": user_id}
    )


@app.get("/hackerview")
def hackerview(
    request: Request,
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user),
):
    user = db.scalars(
        select(User).where(User.id == user_id)
    ).first()

    if not user:
        return RedirectResponse(url="/login")

    return templates.TemplateResponse(
        request,
        "hackerview.html",
        {"user_id": user.id}
    )


@app.get("/api/experiments")
def experiment_history(
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user),
):
    rows = db.scalars(
        select(ExperimentResult).order_by(ExperimentResult.created_at.desc()).limit(200)
    ).all()

    return [
        {
            "id": row.id,
            "experiment_type": row.experiment_type,
            "configuration": row.configuration,
            "attack_type": row.attack_type,
            "result": row.result,
            "latency_ms": row.latency_ms,
            "session_id": row.session_id,
            "detail": json.loads(row.detail_json) if row.detail_json else None,
            "created_at": row.created_at.isoformat(),
        }
        for row in rows
    ]


@app.get("/api/pqc-status")
def pqc_status():
    from crypto_engine import PQC_IMPORT_ERROR

    return {
        "pqc_available": PQC_AVAILABLE,
        "error": PQC_IMPORT_ERROR,
    }


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    token = websocket.cookies.get("access_token")

    if not token:
        if SECURITY_CONFIG["websocket_authentication"]:
            event = create_security_event(
                event_type="UNAUTHORIZED_WEBSOCKET",
                status="BLOCKED",
                message="WebSocket connection attempted without authentication",
            )
            await manager.send_security_event(event)
            await websocket.close(code=1008)
            return

        # websocket_authentication is OFF — this is the live demo of
        # "security off -> attack succeeds": we actually let the
        # unauthenticated connection through instead of just saying we
        # would have.
        user_id = next(_anonymous_id_counter)
        event = create_security_event(
            event_type="UNAUTHORIZED_WEBSOCKET",
            status="VULNERABLE",
            message=f"WebSocket authentication is OFF — accepted an unauthenticated connection as ANONYMOUS ({user_id}).",
            source=user_id,
        )
        await manager.send_security_event(event)

    else:
        try:
            cleaned_token = token.replace("Bearer ", "")
            payload = decode_access_token(cleaned_token)
            user_id = int(payload["sub"])
        except Exception:
            if SECURITY_CONFIG["jwt_authentication"]:
                event = create_security_event(
                    event_type="INVALID_JWT",
                    status="BLOCKED",
                    message="WebSocket connection attempted with an invalid JWT",
                )
                await manager.send_security_event(event)
                await websocket.close(code=1008)
                return

            # jwt_authentication is OFF — trust the token's claims without
            # verifying its signature or expiry, and let the connection
            # through. If it isn't even parseable at all, fall back to an
            # anonymous id rather than crashing the handler.
            try:
                cleaned_token = token.replace("Bearer ", "")
                unverified_payload = decode_access_token_unverified(cleaned_token)
                user_id = int(unverified_payload["sub"])
            except Exception:
                user_id = next(_anonymous_id_counter)

            event = create_security_event(
                event_type="INVALID_JWT",
                status="VULNERABLE",
                message=f"JWT authentication is OFF — accepted an unverified/invalid token as user {user_id}.",
                source=user_id,
            )
            await manager.send_security_event(event)

    await manager.connect(user_id, websocket)

    # ------------------------------------------------------------------
    # REAL handshake — runs an actual X25519+Ed25519 (classical/"tls")
    # or ML-KEM-768+ML-DSA-65 (ml_kem) key exchange, timed with
    # perf_counter(), and stores the resulting session key for this
    # user. This is what SECURITY_CONFIG["encryption"] later uses to
    # actually seal traffic — not a narrated number.
    # ------------------------------------------------------------------
    if SECURITY_CONFIG["tls"] or SECURITY_CONFIG["ml_kem"]:
        try:
            handshake, was_resumed, elapsed_ms = resume_or_handshake(
                user_id,
                use_pqc=SECURITY_CONFIG["ml_kem"],
                allow_resume=SECURITY_CONFIG["session_caching"],
            )
            manager.session_crypto[user_id] = handshake

            base_config = "ml_kem" if SECURITY_CONFIG["ml_kem"] else "tls_classical"

            db = SessionLocal()
            try:
                db.add(ExperimentResult(
                    experiment_type="HANDSHAKE_RESUMED" if was_resumed else "HANDSHAKE",
                    configuration=f"{base_config}_resumed" if was_resumed else base_config,
                    result="MEASURED",
                    latency_ms=elapsed_ms,
                    detail_json=json.dumps({
                        "kem_algorithm": handshake.kem_algorithm,
                        "sig_algorithm": handshake.sig_algorithm,
                        "public_key_size": handshake.public_key_size,
                        "ciphertext_or_ephemeral_size": handshake.ciphertext_or_ephemeral_size,
                        "signature_size": handshake.signature_size,
                        "timings_ms": handshake.timings_ms,
                        "resumed_from_cache": was_resumed,
                    }),
                    session_id=_current_benchmark_session_id(),
                ))
                db.commit()
            finally:
                db.close()

            if was_resumed:
                await manager.send_security_event(create_security_event(
                    event_type="HANDSHAKE_RESUMED",
                    status="MEASURED",
                    message=(
                        f"Resumed a cached {handshake.kem_algorithm}/{handshake.sig_algorithm} "
                        f"session key in {elapsed_ms:.4f}ms — no new handshake was needed "
                        f"(session_caching is ON, and a valid cache entry existed for this user)."
                    ),
                    source=user_id,
                ))
            else:
                await manager.send_security_event(create_security_event(
                    event_type="HANDSHAKE_COMPLETE",
                    status="MEASURED",
                    message=(
                        f"{handshake.kem_algorithm} key exchange + {handshake.sig_algorithm} "
                        f"signature completed in {handshake.timings_ms['total_ms']:.2f}ms "
                        f"(pubkey {handshake.public_key_size}B, "
                        f"ciphertext/ephemeral {handshake.ciphertext_or_ephemeral_size}B, "
                        f"signature {handshake.signature_size}B)."
                    ),
                    source=user_id,
                ))
        except Exception as exc:
            await manager.send_security_event(create_security_event(
                event_type="HANDSHAKE_FAILED",
                status="WARNING",
                message=f"Handshake could not complete: {exc}",
                source=user_id,
            ))

    try:
        while True:
            data = await websocket.receive_json()

            # ------------------------------------------------------------------
            # REAL per-medium chat latency. The client measures its own
            # full round trip (send -> server -> echoed back) on its own
            # clock, so there's no cross-machine clock-skew problem, and
            # reports it here tagged with which medium actually carried
            # that message (PLAINTEXT vs ENCRYPTED, from the real packet
            # this server built when it sent it — see below).
            # ------------------------------------------------------------------
            if data.get("type") == "latency_report":
                rtt_ms = data.get("rtt_ms")
                security_mode = data.get("security_mode", "UNKNOWN")

                if isinstance(rtt_ms, (int, float)) and rtt_ms >= 0:
                    db = SessionLocal()
                    try:
                        db.add(ExperimentResult(
                            experiment_type="MESSAGE_LATENCY",
                            configuration=security_mode,
                            result="MEASURED",
                            latency_ms=float(rtt_ms),
                            detail_json=json.dumps({
                                "client_msg_id": data.get("client_msg_id"),
                                "security_mode": security_mode,
                                "user_id": user_id,
                            }),
                            session_id=_current_benchmark_session_id(),
                        ))
                        db.commit()
                    finally:
                        db.close()

                    await manager.send_to_dashboards({
                        "type": "message_latency",
                        "user_id": user_id,
                        "security_mode": security_mode,
                        "rtt_ms": rtt_ms,
                    })

                continue

            recipient_id = int(data["recipient_id"])
            text = data["text"]
            client_msg_id = data.get("client_msg_id")

            timestamp = datetime.now(timezone.utc).isoformat()

            packet = {
                "timestamp": timestamp,
                "source": user_id,
                "destination": recipient_id,
                "message": text,
                "size": len(text.encode("utf-8")),
                "security_mode": "PLAINTEXT"
            }

            # ------------------------------------------------------------------
            # REAL encryption of what the Hacker Viewer (the eavesdropper
            # channel) sees. The two chat participants still get plaintext
            # over their own authenticated /ws connection — this models
            # an eavesdropper on the wire between server and monitoring
            # tap, not a change to who's allowed to read their own chat.
            # When encryption is ON, `packet["message"]` below is real
            # AES-256-GCM ciphertext; the viewer genuinely cannot recover
            # the text without the session key.
            # ------------------------------------------------------------------
            session = manager.session_crypto.get(user_id)

            if SECURITY_CONFIG["encryption"] and session is not None:
                seal = seal_message(
                    text.encode("utf-8"),
                    session.session_key,
                    sign=SECURITY_CONFIG["message_integrity"],
                    use_pqc_signature=SECURITY_CONFIG["ml_dsa"],
                )
                manager.last_message_seal[user_id] = seal
                manager.seen_nonces.setdefault(user_id, set()).add(seal.nonce)

                packet["message"] = base64.b64encode(seal.ciphertext).decode("ascii")
                packet["nonce"] = base64.b64encode(seal.nonce).decode("ascii")
                packet["security_mode"] = f"ENCRYPTED ({seal.algorithm})"
                packet["size"] = len(seal.ciphertext)
                if seal.signature:
                    packet["signed"] = True
                    packet["sig_algorithm"] = seal.sig_algorithm
                    packet["signature_size"] = len(seal.signature)
            elif SECURITY_CONFIG["encryption"] and session is None:
                packet["security_mode"] = "ENCRYPTION ON — NO SESSION KEY (enable TLS or ML-KEM first)"

            # The delivered message carries the REAL medium tag and the
            # client's own message id back to it, so the browser can match
            # its round trip to the exact medium the server actually used —
            # not whatever the client assumed client-side.
            message = {
                "userId": user_id,
                "recipient_id": recipient_id,
                "text": text,
                "time": timestamp,
                "client_msg_id": client_msg_id,
                "security_mode": packet["security_mode"],
                "execution": "real" if not SECURITY_CONFIG["input_validation"] else "blocked",
            }

            db = SessionLocal()
            try:
                db.add(Message(
                    sender_id=user_id,
                    recipient_id=recipient_id,
                    text=text,
                    created_at=datetime.fromisoformat(timestamp),
                ))
                db.commit()
            finally:
                db.close()

            await manager.send_to_user(user_id, message)
            await manager.send_to_user(recipient_id, message)

            await manager.send_to_viewers(packet)

    except WebSocketDisconnect:
        manager.disconnect(user_id)


@app.websocket("/ws/viewer")
async def viewer_websocket(websocket: WebSocket):

    token = websocket.cookies.get("access_token")

    if not token:
        await websocket.close(code=1008)
        return

    try:
        token = token.replace("Bearer ", "")
        payload = decode_access_token(token)
        user_id = int(payload["sub"])
    except Exception:
        await websocket.close(code=1008)
        return

    await manager.connect_viewer(websocket)

    try:
        while True:
            await websocket.receive_text()

    except WebSocketDisconnect:
        manager.disconnect_viewer(websocket)

@app.websocket("/ws/dashboard")
async def dashboard_websocket(websocket: WebSocket):

    token = websocket.cookies.get("access_token")

    if not token:
        await websocket.close(code=1008)
        return

    try:
        token = token.replace("Bearer ", "")
        payload = decode_access_token(token)
        user_id = int(payload["sub"])
    except Exception:
        await websocket.close(code=1008)
        return

    await manager.connect_dashboard(websocket)

    try:
        await websocket.send_json({
            "type": "security_config",
            "config": SECURITY_CONFIG
        })

        while True:

            command = await websocket.receive_json()

            action = command.get("action")

            if action == "GET_CONFIG":

                await websocket.send_json({
                    "type": "security_config",
                    "config": SECURITY_CONFIG
                })

            elif action == "SET_SECURITY":

                layer = command.get("layer")
                enabled = command.get("enabled")

                if layer in SECURITY_CONFIG:
                    SECURITY_CONFIG[layer] = bool(enabled)

                    event = create_security_event(
                        event_type="SECURITY_CONFIGURATION",
                        status="UPDATED",
                        message=f"{layer} set to {enabled}",
                        source=user_id
                    )

                    await manager.send_security_event(event)

                    await websocket.send_json({
                        "type": "security_config",
                        "config": SECURITY_CONFIG
                    })

            elif action == "RUN_ATTACK":

                attack_type = command.get("attack")

                event = security_engine.run_attack(
                    attack_type,
                    source=user_id
                )

                await manager.send_security_event(event)

            elif action == "RUN_BENCHMARK":

                if ACTIVE_BENCHMARK_SESSION["id"] is not None:
                    await websocket.send_json({
                        "type": "benchmark_error",
                        "message": "A benchmark is already running — wait for it to finish.",
                    })
                else:
                    duration_seconds = int(command.get("duration_seconds", 60))
                    duration_seconds = max(10, min(duration_seconds, 300))

                    session_id = uuid.uuid4().hex[:12]
                    ACTIVE_BENCHMARK_SESSION["id"] = session_id
                    ACTIVE_BENCHMARK_SESSION["ends_at"] = time.time() + duration_seconds

                    await manager.send_security_event(create_security_event(
                        event_type="BENCHMARK_STARTED",
                        status="RUNNING",
                        message=(
                            f"Benchmark session {session_id} started — running for "
                            f"{duration_seconds}s. Any real /ws handshake or chat "
                            f"message sent during this window is captured into "
                            f"this session's results, not just synthetic loop iterations."
                        ),
                        source=user_id,
                    ))

                    asyncio.create_task(run_benchmark_session(session_id, duration_seconds))

            elif action == "RUN_RESUMPTION_BENCHMARK":
                # Real, synchronous measurement (fast — no time-windowed
                # session needed): full handshake vs cached-session
                # lookup, both timed with perf_counter() in
                # crypto_engine.run_resumption_benchmark(). Not a
                # simulated or assumed speedup — whatever percentage
                # comes back is what this run actually measured.
                iterations = int(command.get("iterations", 20))
                iterations = max(5, min(iterations, 100))

                result = run_resumption_benchmark(iterations=iterations)

                db = SessionLocal()
                try:
                    db.add(ExperimentResult(
                        experiment_type="RESUMPTION_BENCHMARK",
                        configuration="session_caching_comparison",
                        result="MEASURED",
                        latency_ms=result["avg_resumed_lookup_ms"],
                        detail_json=json.dumps(result),
                        session_id=_current_benchmark_session_id(),
                    ))
                    db.commit()
                finally:
                    db.close()

                await websocket.send_json({
                    "type": "resumption_benchmark_result",
                    "result": result,
                })

    except WebSocketDisconnect:
        manager.disconnect_dashboard(websocket)


@app.get("/register")
def register_page(request: Request, user_id: int | None = Depends(get_current_user_optional)):
    return templates.TemplateResponse(
        request,
        "register.html",
        {"user_id": user_id}
    )

@app.get("/chat")
def chat_page(
    request: Request,
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user),
):
    user = db.scalars(
        select(User).where(User.id == user_id)
    ).first()

    if not user:
        return RedirectResponse(url="/login")

    return templates.TemplateResponse(
        request,
        "chat.html",
        {
            "user_id": user.id,
            "input_validation": SECURITY_CONFIG["input_validation"],
        }
    )


@app.get("/api/chat-users")
def chat_users(
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user),
):
    users = db.scalars(select(User).where(User.id != user_id).order_by(User.name)).all()
    return [{"id": user.id, "name": user.name} for user in users]


@app.get("/api/messages/{other_user_id}")
def chat_history(
    other_user_id: int,
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user),
):
    rows = db.scalars(
        select(Message).where(
            ((Message.sender_id == user_id) & (Message.recipient_id == other_user_id))
            | ((Message.sender_id == other_user_id) & (Message.recipient_id == user_id))
        ).order_by(Message.created_at)
    ).all()
    return [
        {
            "userId": row.sender_id,
            "recipient_id": row.recipient_id,
            "text": row.text,
            "time": row.created_at.isoformat(),
            "security_mode": "HISTORY",
        }
        for row in rows
    ]


@app.get("/profile/{profile_id}")
def profile_page(
    profile_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user),
):
    user = db.scalars(
        select(User).where(User.id == profile_id)
    ).first()

    if not user:
        return templates.TemplateResponse(
            request,
            "login.html"
        )

    return templates.TemplateResponse(
        request,
        "profile.html",
        {"user": user, "user_id": user_id}
    )


@app.post("/submit")
def submit_post(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    password = hash_password(password)

    user = User(
        name=name,
        email=email,
        password_hash=password
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return templates.TemplateResponse(
        request,
        "submit.html",
        {
            "name": name,
            "email": email,
            "password_hash": user.password_hash,
            "id": user.id
        }
    )


@app.get("/users")
def load_all_users(
    request: Request,
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user),
):
    # Was previously public and rendered every user's password_hash in
    # plain HTML — a real credential leak, not a Hacker View simulation.
    # Now requires login, and the template no longer shows hashes to
    # anyone (see templates/users.html and the DATABASE_LEAK_SIMULATION
    # attack in security_engine.py for the intentional, contained demo
    # of what a real leak like this would expose).
    users = db.scalars(
        select(User)
    ).all()

    return templates.TemplateResponse(
        request,
        "users.html",
        {"users": users, "user_id": user_id}
    )


@app.get("/login")
def login_page(request: Request, user_id: int | None = Depends(get_current_user_optional)):
    return templates.TemplateResponse(
        request,
        "login.html",
        {"user_id": user_id}
    )


@app.get("/logout")
def logout(request: Request):
    """
    Clears the auth cookie and sends the visitor home. Uses delete_cookie
    (not just an expired set_cookie) so the browser actually drops it,
    and matches the exact key/path the login flow set it with. Also
    invalidates any cached session-resumption key for this user — a
    logged-out session shouldn't let a later reconnect skip the
    handshake using a key derived while they were still logged in.
    """
    token = request.cookies.get("access_token")
    if token:
        try:
            payload = decode_access_token(token.replace("Bearer ", ""))
            SESSION_CACHE.invalidate(int(payload["sub"]))
        except Exception:
            pass

    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie(key="access_token")
    return response


@app.post("/login")
def login_post(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = db.scalars(
        select(User).where(User.email == email)
    ).first()

    if user and verify_password(password, user.password_hash):
        token = create_access_token(user.id)

        response = templates.TemplateResponse(
            request,
            "login_success.html",
            {
                "name": user.name,
                "email": user.email
            }
        )

        response.set_cookie(
            key="access_token",
            value=f"Bearer {token}",
            httponly=True
        )

        return response

    return templates.TemplateResponse(
        request,
        "login_failure.html"
    )


@app.get("/protected", response_class=HTMLResponse)
def protected(
    request: Request,
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user)
):
    user = db.scalars(
        select(User).where(User.id == user_id)
    ).first()

    if not user:
        return templates.TemplateResponse(
            request,
            "login_failure.html"
        )

    return templates.TemplateResponse(
        request,
        "protected.html",
        {
            "name": user.name,
            "email": user.email,
            "Message": "Authenticated",
            "user_id": user_id,
        }
    )

@app.get("/dashboard")
def dashboard(
    request: Request,
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user),
):
    user = db.scalars(
        select(User).where(User.id == user_id)
    ).first()

    if not user:
        return RedirectResponse(url="/login")

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {"user_id": user.id}
    )