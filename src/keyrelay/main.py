from __future__ import annotations

import hmac
import logging
import os
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse

import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from .browser import LoginBroker
from .security import VaultCipher, host_is_public, load_or_create_secret, validate_login_url
from .store import Site, VaultStore

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("keyrelay")

DATA_DIR = Path(os.getenv("KEYRELAY_DATA_DIR", ".data")).resolve()
STATIC_DIR = Path(__file__).with_name("static")
ADMIN_TOKEN = load_or_create_secret(DATA_DIR / "admin.token").hex()
BOT_TOKEN = load_or_create_secret(DATA_DIR / "bot.token").hex()
STORE = VaultStore(DATA_DIR / "vault.db", VaultCipher(load_or_create_secret(DATA_DIR / "vault.key")))
BROKER = LoginBroker(
    DATA_DIR / "browser-profile",
    headless=os.getenv("KEYRELAY_HEADLESS", "false").lower() == "true",
)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    yield
    await BROKER.close()


app = FastAPI(
    title="KeyRelay",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
attempts: dict[str, deque[float]] = defaultdict(deque)


class SiteInput(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    login_url: str
    username: str = Field(min_length=1, max_length=500)
    password: str = Field(min_length=1, max_length=2000)
    username_selector: str = Field(min_length=1, max_length=300)
    password_selector: str = Field(min_length=1, max_length=300)
    submit_selector: str = Field(min_length=1, max_length=300)
    allowed_hosts: list[str] = Field(default_factory=list, max_length=10)

    @field_validator("login_url")
    @classmethod
    def valid_url(cls, value: str) -> str:
        return validate_login_url(value)

    @field_validator("allowed_hosts")
    @classmethod
    def valid_hosts(cls, values: list[str]) -> list[str]:
        clean = []
        for value in values:
            host = value.strip().lower().rstrip(".")
            if not host or "/" in host or ":" in host:
                raise ValueError("允许域名只能填写主机名")
            clean.append(host)
        return list(dict.fromkeys(clean))


def public_site(site: Site) -> dict[str, object]:
    return {
        "id": site.id,
        "name": site.name,
        "login_url": site.login_url,
        "allowed_hosts": site.allowed_hosts,
    }


def verify_token(actual: str | None, expected: str, label: str) -> None:
    if not actual or not hmac.compare_digest(actual, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"{label}令牌无效")


def require_admin(x_keyrelay_admin: str | None = Header(default=None)) -> None:
    verify_token(x_keyrelay_admin, ADMIN_TOKEN, "管理")


def require_bot(request: Request, x_keyrelay_token: str | None = Header(default=None)) -> None:
    verify_token(x_keyrelay_token, BOT_TOKEN, "Bot")
    client = request.client.host if request.client else "unknown"
    now = time.monotonic()
    recent = attempts[client]
    while recent and recent[0] < now - 60:
        recent.popleft()
    if len(recent) >= 10:
        raise HTTPException(status_code=429, detail="请求过于频繁")
    recent.append(now)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; frame-ancestors 'none'; form-action 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.get("/")
async def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/api/v1/sites", dependencies=[Depends(require_admin)])
async def list_sites():
    return [public_site(site) for site in STORE.list_sites()]


@app.post("/api/v1/sites", status_code=201, dependencies=[Depends(require_admin)])
async def create_site(payload: SiteInput):
    login_host = (urlparse(payload.login_url).hostname or "").lower()
    allowed_hosts = list(dict.fromkeys([login_host, *payload.allowed_hosts]))
    unsafe = [host for host in allowed_hosts if not host_is_public(host)]
    if unsafe:
        raise HTTPException(
            status_code=400,
            detail=f"域名无法解析到公共网络地址：{', '.join(unsafe)}",
        )
    site = STORE.create_site(
        **payload.model_dump(exclude={"allowed_hosts"}),
        allowed_hosts=allowed_hosts,
    )
    logger.info("Saved login recipe site_id=%s host=%s", site.id, login_host)
    return public_site(site)


@app.delete("/api/v1/sites/{site_id}", dependencies=[Depends(require_admin)])
async def delete_site(site_id: str):
    if not STORE.delete_site(site_id):
        raise HTTPException(status_code=404, detail="网站不存在")
    return {"status": "deleted"}


@app.post("/api/v1/login/{site_id}", dependencies=[Depends(require_bot)])
async def login(site_id: str):
    try:
        site, credentials = STORE.get_site(site_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="网站不存在") from None
    logger.info("Bot requested login site_id=%s", site.id)
    try:
        return await BROKER.login(site, credentials)
    except Exception as exc:
        logger.warning("Login failed site_id=%s error_type=%s", site.id, type(exc).__name__)
        raise HTTPException(
            status_code=502,
            detail="浏览器登录失败。请检查选择器、网络和浏览器安装状态。",
        ) from exc


def run() -> None:
    port = int(os.getenv("PORT", "43127"))
    print(f"\nKeyRelay 管理令牌：{ADMIN_TOKEN}")
    print(f"KeyRelay Bot 令牌：{BOT_TOKEN}")
    print("令牌也保存在 .data/，不要提交或发送给他人。\n")
    uvicorn.run("keyrelay.main:app", host="127.0.0.1", port=port)


if __name__ == "__main__":
    run()
