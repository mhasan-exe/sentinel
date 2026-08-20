from pwdlib import PasswordHash
import jwt
import os
from datetime import datetime, timedelta,timezone
from fastapi import HTTPException, status, Depends,Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

bearer_scheme = HTTPBearer()

def get_current_user(request: Request):
    token_cookie = request.cookies.get("access_token")
    
    if not token_cookie:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Session signature missing, please log in."
        )
        
    try:
        token = token_cookie.replace("Bearer ", "")
        payload = decode_access_token(token)
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload data.")
            
        return int(user_id)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Expired or corrupt auth session key.")

SECRET_KEY = os.environ.get("SENTINEL_SECRET_KEY")
if not SECRET_KEY:
    # Dev-only fallback so the app still runs without setup. This key is
    # public (it's in this source file's git history) — never rely on it
    # outside a local demo, and set SENTINEL_SECRET_KEY before deploying
    # or presenting from a shared/public machine.
    SECRET_KEY = "dev-only-insecure-key-set-SENTINEL_SECRET_KEY-env-var"
    print(
        "[security.py] WARNING: SENTINEL_SECRET_KEY not set — using an "
        "insecure development fallback key. Set it in your environment "
        "or .env file for anything beyond local testing."
    )
ALGORITHM = "HS256"

password_hash = PasswordHash.recommended()
def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    return password_hash.verify(password, hashed_password)

def create_access_token(user_id: int):
    expire = datetime.now(timezone.utc) + timedelta(minutes=30)
    payload = {
        "sub": str(user_id),
        "exp": expire
    }
    return jwt.encode(payload,SECRET_KEY,algorithm=ALGORITHM)

def decode_access_token(token: str):
    return jwt.decode(
        token,
        SECRET_KEY,
        algorithms=[ALGORITHM]
        )


def decode_access_token_unverified(token: str):
    """
    Decode a token WITHOUT checking its signature or expiry.

    Only ever called from main.py's /ws handler, and only when
    SECURITY_CONFIG["jwt_authentication"] has deliberately been switched
    OFF from the dashboard — this is what makes that toggle demo real
    instead of simulated: with JWT auth off, a forged/expired token's
    claims are trusted as-is.
    """
    return jwt.decode(
        token,
        options={"verify_signature": False, "verify_exp": False},
    )