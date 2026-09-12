from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from .config import get_settings
from .database import init_db
from .seed import run_seed
from .ws import manager
from .deps import get_current_user
from .routers import auth as auth_router, events as events_router, security as security_router, config as config_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    run_seed()
    yield


app = FastAPI(title="CHEKWE — Security Operations & Defense Platform",
              description="Defensive SOC platform: ingestion, detection, correlation, "
                          "incidents, AI analysis, controlled response.",
              version="0.1.0", lifespan=lifespan)

s = get_settings()
app.add_middleware(CORSMiddleware, allow_origins=s.cors_list, allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])


@app.get("/api/v1/meta")
def meta():
    return {"app": "CHEKWE", "tagline": "DETECT. UNDERSTAND. RESPOND.",
            "creator": "Anonymous-beta"}


for r in (auth_router.router, events_router.router, security_router.router, config_router.router):
    app.include_router(r, prefix="/api/v1")


@app.websocket("/ws/events")
async def ws_events(websocket: WebSocket, user=Depends(get_current_user)):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()  # keepalive
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
