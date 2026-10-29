"""
Легковесный HTTP-сервер на aiohttp для обслуживания Web App статики
и проверки initData + доступа пользователя.

Маршруты:
  GET  /          → webapp/index.html
  GET  /static/*  → статические файлы
  POST /api/check → проверка initData + доступа (возвращает JSON)
"""
from __future__ import annotations

import json
import logging
import mimetypes
from pathlib import Path

from aiohttp import web

from config import cfg
from database.db import get_db
from bot.services.init_data import validate_init_data

logger = logging.getLogger(__name__)

WEBAPP_DIR = Path(__file__).parent


async def handle_index(request: web.Request) -> web.Response:
    """Отдаём index.html."""
    index_path = WEBAPP_DIR / "index.html"
    if not index_path.exists():
        raise web.HTTPNotFound()
    return web.FileResponse(index_path)


async def handle_static(request: web.Request) -> web.Response:
    """Отдаём статические файлы из webapp/static/."""
    filename = request.match_info["filename"]
    # Защита от path traversal
    static_dir = WEBAPP_DIR / "static"
    file_path = (static_dir / filename).resolve()
    if not str(file_path).startswith(str(static_dir.resolve())):
        raise web.HTTPForbidden()
    if not file_path.exists() or not file_path.is_file():
        raise web.HTTPNotFound()

    content_type, _ = mimetypes.guess_type(str(file_path))
    return web.FileResponse(file_path, headers={"Content-Type": content_type or "application/octet-stream"})


async def handle_check(request: web.Request) -> web.Response:
    """
    POST /api/check
    Body JSON: {"init_data": "<telegram initData string>"}
    
    Проверяет:
    1. HMAC-подпись initData
    2. Активный доступ пользователя в БД
    
    Returns JSON: {"ok": true/false, "message": "..."}
    """
    try:
        body = await request.json()
    except Exception:
        return _json_error("Invalid JSON body", status=400)

    init_data_str = body.get("init_data", "")
    if not init_data_str:
        return _json_error("Missing init_data", status=400)

    # 1. Проверяем HMAC-подпись
    parsed = validate_init_data(init_data_str, cfg.bot_token)
    if parsed is None:
        logger.warning("Invalid initData received from %s", request.remote)
        return _json_error("Invalid initData signature", status=403)

    # 2. Извлекаем user_id
    user_data = parsed.get("user")
    if not user_data or not isinstance(user_data, dict):
        return _json_error("No user data in initData", status=403)

    user_id = user_data.get("id")
    if not user_id:
        return _json_error("No user ID in initData", status=403)

    # 3. Проверяем доступ в БД
    try:
        db = get_db()
        has_access = await db.has_active_access(int(user_id))
    except Exception as exc:
        logger.error("DB error during access check: %s", exc)
        return _json_error("Internal server error", status=500)

    if not has_access:
        return web.Response(
            content_type="application/json",
            text=json.dumps({"ok": False, "message": "No active access"}),
            status=403,
        )

    return web.Response(
        content_type="application/json",
        text=json.dumps({"ok": True, "user_id": user_id, "message": "Access granted"}),
    )


def _json_error(message: str, status: int = 400) -> web.Response:
    return web.Response(
        content_type="application/json",
        text=json.dumps({"ok": False, "message": message}),
        status=status,
    )


def create_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/", handle_index)
    app.router.add_get("/static/{filename:.+}", handle_static)
    app.router.add_post("/api/check", handle_check)
    return app
