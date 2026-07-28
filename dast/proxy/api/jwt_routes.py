"""
JWT editor routes — decode, edit, and re-sign JWTs for the Extras > JWT tab.

POST /api/jwt/build — build a signed (or unsigned) JWT from a header + payload.

This is a manual toolbelt endpoint: the operator pastes
a token in the UI, edits the decoded header/payload, picks a signing mode, and gets
back a re-signed token to send to Repeater. All signing reuses the trusted helpers in
`dast.plugins.jwt_tester` so encoding stays consistent with the automated JWT agent.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from dast.plugins.jwt_tester import _build_token
from dast.proxy.api.context import DashboardContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_ALG_BY_MODE = {"hs256": "HS256", "hs384": "HS384", "hs512": "HS512", "none": "none"}


class JwtBuildRequest(BaseModel):
    header: Dict[str, Any]
    payload: Dict[str, Any]
    mode: str = "hs256"
    secret: Optional[str] = None


def make_router(ctx: DashboardContext) -> APIRouter:
    router = APIRouter()

    @router.post("/api/jwt/build")
    async def build_jwt(req: JwtBuildRequest) -> dict:
        mode = (req.mode or "hs256").lower()
        if mode not in _ALG_BY_MODE:
            logger.warning("jwt build rejected", mode=mode)
            return JSONResponse(
                {"error": f"unsupported signing mode: {mode!r}"}, status_code=400
            )

        header = dict(req.header)
        header["alg"] = _ALG_BY_MODE[mode]

        if mode == "none":
            secret: Optional[str] = None
        else:
            secret = req.secret or ""

        try:
            token = _build_token(header, dict(req.payload), secret=secret)
        except Exception as exc:
            logger.error("jwt build failed", error=str(exc))
            return JSONResponse({"error": f"build failed: {exc}"}, status_code=400)

        logger.info("jwt build", mode=mode, alg=header["alg"])
        return {"token": token, "alg": header["alg"]}

    return router
