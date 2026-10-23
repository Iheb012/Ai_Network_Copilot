"""API-key authentication for the AI Network Copilot API.

Key lookup order:
  1. AI_COPILOT_API_KEY environment variable (use this in Docker / servers)
  2. <project>/data/.api_key (auto-created on first start, never committed)

Set AI_COPILOT_DISABLE_AUTH=1 to turn authentication off (development only).
REST requests must send the key in the  X-API-Key  header.
WebSocket connections may send the same header or  ?api_key=<key>  because
browsers cannot set custom headers on WebSockets.
/health, /docs, /redoc and /openapi.json stay public.
"""
import hmac
import os
import secrets
from pathlib import Path

from fastapi import HTTPException, WebSocketException
from starlette.requests import HTTPConnection

PROJECT_ROOT = Path(__file__).resolve().parent.parent
KEY_FILE = PROJECT_ROOT / "data" / ".api_key"
PUBLIC_PATHS = {"/health", "/docs", "/redoc", "/openapi.json"}


def load_api_key() -> str:
    env_key = os.getenv("AI_COPILOT_API_KEY", "").strip()
    if env_key:
        return env_key
    try:
        if KEY_FILE.exists():
            stored = KEY_FILE.read_text(encoding="utf-8").strip()
            if stored:
                return stored
        KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
        new_key = secrets.token_urlsafe(32)
        KEY_FILE.write_text(new_key, encoding="utf-8")
        try:
            os.chmod(KEY_FILE, 0o600)
        except OSError:
            pass  # not supported on some Windows filesystems
        return new_key
    except OSError:
        # Cannot persist a key: use a per-process key rather than no auth.
        return secrets.token_urlsafe(32)


AUTH_DISABLED = os.getenv("AI_COPILOT_DISABLE_AUTH", "").lower() in ("1", "true", "yes")
API_KEY = load_api_key()


def _key_ok(supplied) -> bool:
    return bool(supplied) and hmac.compare_digest(str(supplied), API_KEY)


async def require_api_key(conn: HTTPConnection) -> None:
    """Global dependency: protects every REST route and WebSocket."""
    if AUTH_DISABLED or conn.url.path in PUBLIC_PATHS:
        return
    supplied = conn.headers.get("x-api-key")
    if not supplied and conn.scope["type"] == "websocket":
        supplied = conn.query_params.get("api_key")
    if _key_ok(supplied):
        return
    if conn.scope["type"] == "websocket":
        raise WebSocketException(code=1008)  # policy violation
    raise HTTPException(status_code=401, detail="Missing or invalid API key")
