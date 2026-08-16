from fastapi import FastAPI, Request, Form, Depends, WebSocket, WebSocketDisconnect
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse, HTMLResponse
from sqlalchemy.orm import Session
from sqlalchemy import select
from datetime import datetime, timezone

from database import SessionLocal
from models import User
from security import (
    hash_password,
    verify_password,
    get_current_user,
    create_access_token,
    decode_access_token,
)
from connection_manager import manager
from security_events import create_security_event
from security_config import SECURITY_CONFIG

app = FastAPI()
templates = Jinja2Templates(directory="templates")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.get("/")
def homepage(request: Request):
    return templates.TemplateResponse(
        request,
        "layout.html"
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


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    token = websocket.cookies.get("access_token")

    if not token:
        event = create_security_event(
        event_type="UNAUTHORIZED_WEBSOCKET",
        status="BLOCKED",
        message="WebSocket connection attempted without authentication"
        )

        await manager.send_security_event(event)

        await websocket.close(code=1008)
        return

    try:
        token = token.replace("Bearer ", "")
        payload = decode_access_token(token)
        user_id = int(payload["sub"])
    except Exception:
        event = create_security_event(
        event_type="INVALID_JWT",
        status="BLOCKED",
        message="WebSocket connection attempted with an invalid JWT"
        )

        await manager.send_security_event(event)
        await websocket.close(code=1008)
        return

    await manager.connect(user_id, websocket)

    try:
        while True:
            data = await websocket.receive_json()

            recipient_id = int(data["recipient_id"])
            text = data["text"]

            timestamp = datetime.now(timezone.utc).isoformat()

            message = {
                "userId": user_id,
                "recipient_id": recipient_id,
                "text": text,
                "time": timestamp
            }

            packet = {
                "timestamp": timestamp,
                "source": user_id,
                "destination": recipient_id,
                "message": text,
                "size": len(text.encode("utf-8")),
                "security_mode": "PLAINTEXT"
            }

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

@app.get("/register")
def register_page(request: Request):
    return templates.TemplateResponse(
        request,
        "register.html"
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
        {"user_id": user.id}
    )


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
        {"user": user}
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
    db: Session = Depends(get_db)
):
    users = db.scalars(
        select(User)
    ).all()

    return templates.TemplateResponse(
        request,
        "users.html",
        {"users": users}
    )


@app.get("/login")
def login_page(request: Request):
    return templates.TemplateResponse(
        request,
        "login.html"
    )


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
            "Message": "Authenticated"
        }
    )