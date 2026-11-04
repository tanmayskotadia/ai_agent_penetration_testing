"""Bound request bytes before JSON deserialization, including chunked uploads."""

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send


class BodyLimitMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return
        limit = 2097152 if scope["path"].endswith("/original") else 262144
        raw = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            raw.extend(message.get("body", b""))
            if len(raw) > limit:
                await JSONResponse(
                    {"code": "body-too-large", "message": "Request exceeds endpoint byte limit"},
                    413,
                )(scope, receive, send)
                return
            if not message.get("more_body", False):
                break
        consumed = False

        async def replay():  # type: ignore[no-untyped-def]
            nonlocal consumed
            if consumed:
                return await receive()
            consumed = True
            return {"type": "http.request", "body": bytes(raw), "more_body": False}

        await self.app(scope, replay, send)
