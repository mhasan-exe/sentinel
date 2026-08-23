from fastapi import WebSocket


class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[int, set[WebSocket]] = {}
        self.viewer_connections: list[WebSocket] = []
        self.dashboard_connections: list[WebSocket] = []

        # Per-user live crypto state, set once at handshake time in
        # main.py's /ws handler when tls/ml_kem is ON. None means "no
        # handshake happened" (security off, or plaintext mode).
        # Shape: {user_id: crypto_engine.HandshakeResult}
        self.session_crypto: dict[int, object] = {}

        # The most recent REAL sealed message per user, kept so the
        # dashboard's MESSAGE_TAMPERING / REPLAY_TEST buttons can act on
        # actual captured ciphertext instead of a narrated string.
        # Shape: {user_id: crypto_engine.MessageSeal}
        self.last_message_seal: dict[int, object] = {}
        self.last_message_signer_pub: dict[int, object] = {}

        # Real nonce-reuse tracking for the replay-cache check (spec
        # section 10.E). A nonce showing up twice for the same user is a
        # genuine replay, detected by real set membership, not narration.
        self.seen_nonces: dict[int, set] = {}

        # Hacker View INTERCEPT queue (spec section 4). Keyed by a random
        # id so RELEASE/DROP/MODIFY commands from the attacker's
        # dashboard socket can reference one specific pending message,
        # not just "whatever's most recent". Populated in main.py's /ws
        # handler when interception_enabled is ON; drained by the
        # RELEASE_MESSAGE/DROP_MESSAGE actions on /ws/dashboard.
        # Shape: {intercept_id: {...}}
        self.pending_interceptions: dict[str, dict] = {}

    async def connect(self, user_id: int, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.setdefault(user_id, set()).add(websocket)

    def disconnect(self, user_id: int, websocket: WebSocket | None = None):
        sockets = self.active_connections.get(user_id)
        if sockets is not None:
            if websocket is None:
                sockets.clear()
            else:
                sockets.discard(websocket)
            if sockets:
                return
            self.active_connections.pop(user_id, None)
        self.session_crypto.pop(user_id, None)
        self.last_message_seal.pop(user_id, None)
        self.last_message_signer_pub.pop(user_id, None)
        self.seen_nonces.pop(user_id, None)

    async def send_to_user(self, user_id: int, message: dict):
        sockets = self.active_connections.get(user_id, set())
        dead = []
        for websocket in sockets:
            try:
                await websocket.send_json(message)
            except Exception:
                # The recipient's socket died between us looking it up
                # and sending — drop the stale entry instead of letting
                # this bubble up and take down whatever unrelated
                # request (e.g. the SENDER's own /ws loop) was calling
                # send_to_user. This was a real, if intermittent, cause
                # of "the whole chat connection just dropped" reports:
                # one dead recipient socket could crash the sender's turn.
                dead.append(websocket)
        for websocket in dead:
            self.disconnect(user_id, websocket)

    async def send_to_all_users(self, message: dict):
        for user_id in list(self.active_connections):
            await self.send_to_user(user_id, message)

    async def connect_viewer(self, websocket: WebSocket):
        await websocket.accept()
        self.viewer_connections.append(websocket)

    def disconnect_viewer(self, websocket: WebSocket):
        if websocket in self.viewer_connections:
            self.viewer_connections.remove(websocket)

    async def send_to_viewers(self, message: dict):
        dead = []
        for websocket in self.viewer_connections:
            try:
                await websocket.send_json(message)
            except Exception:
                dead.append(websocket)
        for websocket in dead:
            self.disconnect_viewer(websocket)

    async def connect_dashboard(self, websocket: WebSocket):
        await websocket.accept()
        self.dashboard_connections.append(websocket)

    def disconnect_dashboard(self, websocket: WebSocket):
        if websocket in self.dashboard_connections:
            self.dashboard_connections.remove(websocket)

    async def send_security_event(self, event: dict):
        # Persist the same event that is broadcast so the dashboard history
        # and live feed cannot disagree.
        try:
            from database import SessionLocal
            from models import ExperimentResult
            import json
            db = SessionLocal()
            try:
                db.add(ExperimentResult(
                    experiment_type=event.get("event", "SECURITY_EVENT"),
                    configuration="live",
                    attack_type=event.get("event"),
                    result=event.get("status", "UNKNOWN"),
                    latency_ms=None,
                    detail_json=json.dumps(event),
                ))
                db.commit()
            finally:
                db.close()
        except Exception:
            pass

        # Security events go to both the Hacker Viewer and the Dashboard.
        # Previously this only reached viewer_connections, so the
        # dashboard's own "Security Events" panel never lit up.
        dead_viewers = []
        for websocket in self.viewer_connections:
            try:
                await websocket.send_json(event)
            except Exception:
                dead_viewers.append(websocket)
        for websocket in dead_viewers:
            self.disconnect_viewer(websocket)

        dead_dashboards = []
        for websocket in self.dashboard_connections:
            try:
                await websocket.send_json(event)
            except Exception:
                dead_dashboards.append(websocket)
        for websocket in dead_dashboards:
            self.disconnect_dashboard(websocket)

    async def send_to_dashboards(self, message: dict):
        # Benchmark progress / results and real message-latency telemetry
        # go to every open dashboard tab, not just whichever one
        # triggered the action — a second judge watching a second
        # dashboard should see the same live numbers.
        dead = []
        for websocket in self.dashboard_connections:
            try:
                await websocket.send_json(message)
            except Exception:
                dead.append(websocket)
        for websocket in dead:
            self.disconnect_dashboard(websocket)

    async def send_security_config(self, config: dict):
        message = {"type": "security_config", "config": config}
        chat_connections = [
            websocket
            for sockets in self.active_connections.values()
            for websocket in sockets
        ]
        await self._send_to_connections(chat_connections, message)
        await self._send_to_connections(self.viewer_connections, message)
        await self._send_to_connections(self.dashboard_connections, message)

    async def _send_to_connections(self, connections, message: dict):
        for websocket in list(connections):
            try:
                await websocket.send_json(message)
            except Exception:
                if websocket in self.viewer_connections:
                    self.disconnect_viewer(websocket)
                elif websocket in self.dashboard_connections:
                    self.disconnect_dashboard(websocket)


manager = ConnectionManager()