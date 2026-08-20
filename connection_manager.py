from fastapi import WebSocket


class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[int, WebSocket] = {}
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

    async def connect(self, user_id: int, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[user_id] = websocket

    def disconnect(self, user_id: int):
        self.active_connections.pop(user_id, None)
        self.session_crypto.pop(user_id, None)
        self.last_message_seal.pop(user_id, None)
        self.last_message_signer_pub.pop(user_id, None)
        self.seen_nonces.pop(user_id, None)

    async def send_to_user(self, user_id: int, message: dict):
        websocket = self.active_connections.get(user_id)

        if websocket:
            await websocket.send_json(message)

    async def connect_viewer(self, websocket: WebSocket):
        await websocket.accept()
        self.viewer_connections.append(websocket)

    def disconnect_viewer(self, websocket: WebSocket):
        if websocket in self.viewer_connections:
            self.viewer_connections.remove(websocket)

    async def send_to_viewers(self, message: dict):
        for websocket in self.viewer_connections:
            await websocket.send_json(message)

    async def connect_dashboard(self, websocket: WebSocket):
        await websocket.accept()
        self.dashboard_connections.append(websocket)

    def disconnect_dashboard(self, websocket: WebSocket):
        if websocket in self.dashboard_connections:
            self.dashboard_connections.remove(websocket)

    async def send_security_event(self, event: dict):
        # Security events go to both the Hacker Viewer and the Dashboard.
        # Previously this only reached viewer_connections, so the
        # dashboard's own "Security Events" panel never lit up.
        for websocket in self.viewer_connections:
            await websocket.send_json(event)
        for websocket in self.dashboard_connections:
            await websocket.send_json(event)

    async def send_to_dashboards(self, message: dict):
        # Benchmark progress / results and real message-latency telemetry
        # go to every open dashboard tab, not just whichever one
        # triggered the action — a second judge watching a second
        # dashboard should see the same live numbers.
        for websocket in self.dashboard_connections:
            await websocket.send_json(message)


manager = ConnectionManager()