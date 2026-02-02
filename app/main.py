from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from starlette.middleware.sessions import SessionMiddleware

from fido2.webauthn import webauthn_json_mapping

from .db import init_db
from .routes import admin, auth, banking, mfa, poia, webauthn
from .settings import BASE_DIR, SESSION_SECRET

try:
    webauthn_json_mapping.enabled = True
except ValueError:
    pass

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
app.add_middleware(ProxyHeadersMiddleware)
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    detail = f"{type(exc).__name__}: {exc}"
    return JSONResponse(status_code=500, content={"error": "internal_error", "detail": detail})

app.include_router(auth.router)
app.include_router(mfa.router)
app.include_router(webauthn.router)
app.include_router(banking.router)
app.include_router(poia.router)
app.include_router(admin.router)

init_db()
