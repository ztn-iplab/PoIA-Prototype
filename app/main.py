import logging

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .db import init_db
from .routes import admin, auth, banking, mfa, poia, webauthn
from .settings import BASE_DIR, INSECURE_SESSION_SECRETS, POIA_TEST_MODE, SESSION_SECRET

# This is the one place the app actually becomes network-reachable (the session
# cookie gets signed with SESSION_SECRET below). Refuse to boot with a known
# guessable secret -- see app/settings.py for why this check lives here and not
# there. Anyone who knows this value can forge a session for any user.
if SESSION_SECRET in INSECURE_SESSION_SECRETS and not POIA_TEST_MODE:
    raise RuntimeError(
        f"POIA_SESSION_SECRET is missing or set to a known placeholder value "
        f"({SESSION_SECRET!r}). This secret signs session cookies and "
        "password-reset/MFA-enrollment tokens; a known value allows forging a "
        "session for any user. Set a real random secret, e.g. via "
        "`openssl rand -hex 32`, before starting outside of POIA_TEST_MODE."
    )

class ProxyHeadersMiddleware:
    def __init__(self, app: FastAPI) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http":
            headers = {k.decode("latin1"): v.decode("latin1") for k, v in scope.get("headers", [])}
            forwarded_proto = headers.get("x-forwarded-proto")
            forwarded_host = headers.get("x-forwarded-host")
            if forwarded_proto:
                scope = dict(scope)
                scope["scheme"] = forwarded_proto.split(",")[0].strip()
            if forwarded_host:
                host = forwarded_host.split(",")[0].strip()
                if ":" in host:
                    name, port = host.rsplit(":", 1)
                    try:
                        port_value = int(port)
                    except ValueError:
                        port_value = 443
                else:
                    name = host
                    port_value = 443 if scope.get("scheme") == "https" else 80
                scope["server"] = (name, port_value)
        await self.app(scope, receive, send)


app = FastAPI(title="PoIA Banking Prototype")
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["poia.local", "localhost", "127.0.0.1", "testserver"],
)
app.add_middleware(ProxyHeadersMiddleware)
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    same_site="strict",
    max_age=8 * 60 * 60,
    # Starlette defaults https_only to False, which omits the `Secure`
    # cookie attribute -- silently weaker than the "secure, HTTP-only,
    # same-site session cookies" the deployment is documented (Main.tex,
    # Sec. VII.C) as using. The real deployment terminates TLS in front of
    # this app (Sec. VII.C), so this is safe to require unconditionally
    # rather than gate behind an environment flag.
    https_only=True,
)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logging.getLogger("poia").exception("Unhandled request error", exc_info=exc)
    return JSONResponse(status_code=500, content={"error": "internal_error"})

app.include_router(auth.router)
app.include_router(mfa.router)
app.include_router(webauthn.router)
app.include_router(banking.router)
app.include_router(poia.router)
app.include_router(admin.router)

init_db()
