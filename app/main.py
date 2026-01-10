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

app = FastAPI(title="PoIA Banking Prototype")
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
