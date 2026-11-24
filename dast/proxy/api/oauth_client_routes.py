"""OAuth client-credentials routes (4-G): the operator's vault of
client_id/client_secret pairs per IDP host — consumed by the oauth_agent's
code-single-use exchanges. Secrets are Fernet-encrypted at rest and NEVER
returned (reads expose only client_secret_set booleans)."""

from __future__ import annotations


from fastapi import APIRouter
from fastapi.responses import JSONResponse

from dast.profiles.oauth_clients import (credentials_for_host, list_hosts,
                                         remove_for_host, set_for_host)


def make_router(ctx) -> APIRouter:
    router = APIRouter()

    @router.get("/api/oauth-clients")
    async def list_oauth_clients():
        return {"hosts": list_hosts()}

    @router.put("/api/oauth-clients")
    async def set_oauth_client(body: dict):
        host = str(body.get("host", "")).strip()
        client_id = str(body.get("client_id", "")).strip()
        secret = str(body.get("client_secret", "")).strip()
        if not host or not client_id or not secret:
            return JSONResponse({"error": "host, client_id and client_secret "
                                          "are required"}, status_code=400)
        set_for_host(host, client_id, secret)
        return {"ok": True, "host": host.lower(), "client_id": client_id}

    @router.delete("/api/oauth-clients")
    async def delete_oauth_client(body: dict):
        host = str(body.get("host", "")).strip()
        if not host:
            return JSONResponse({"error": "host required"}, status_code=400)
        remove_for_host(host)
        return {"ok": True}

    @router.get("/api/oauth-clients/credentials")
    async def get_credentials(host: str = ""):
        """Agent-facing read: whether credentials exist for a host (the secret
        itself is never returned — the agent reads it from the vault directly)."""
        if not host:
            return JSONResponse({"error": "host required"}, status_code=400)
        creds = credentials_for_host(host)
        return {"host": host, "configured": creds is not None,
                "client_id": creds.client_id if creds else ""}

    return router
