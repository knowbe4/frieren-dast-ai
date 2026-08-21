"""
Profile-based re-authentication — the "replay flow, then saved session" chain.

Given a host and the proxy port, resolve the matching encrypted login profile and
try, in order:
  1. replay the recorded LoginFlow (headless, unattended — no human pause here),
  2. fall back to the profile's saved_session (storage_state) if replay yields nothing.

Returns a Playwright storage_state dict on success (ready for
ContextPool.apply_auth_state), or None if no profile matches / both paths fail.
Human-in-the-loop replay lives in the interactive Logins tab, not this scan-time
path — a background scan has no analyst watching to solve a captcha.
"""

from __future__ import annotations

from typing import Optional

from dast.utils.logger import get_logger

logger = get_logger(__name__)


async def reauth_from_profile(host: str, proxy_port: int) -> Optional[dict]:
    """Resolve a login profile for ``host`` and return a fresh storage_state, or None."""
    if not host:
        return None
    try:
        from dast.profiles.store import resolve_for_host
    except Exception as exc:
        logger.debug("profile re-auth unavailable", error=str(exc))
        return None

    profile = resolve_for_host(host)
    if profile is None:
        return None

    # 1) Replay the recorded flow, unattended.
    if profile.login_flow and profile.login_flow.get("steps"):
        try:
            from dast.profiles.flow import LoginFlow
            from dast.session.flow_replayer import replay_login_flow

            cred = profile.credentials[0] if profile.credentials else None
            result = await replay_login_flow(
                proxy_port=proxy_port,
                flow=LoginFlow.from_dict(profile.login_flow),
                username=cred.username if cred else "",
                password=cred.secret if cred else "",
                headless=True,
                on_pause=None,      # unattended — a captcha simply fails this path
                resume_event=None,
            )
            if result.get("success") and result.get("storage_state"):
                logger.info("profile re-auth succeeded via flow replay",
                            slug=profile.slug, host=host)
                return result["storage_state"]
            logger.warning("profile flow replay produced no session",
                           slug=profile.slug, error=result.get("error", ""))
        except Exception as exc:
            logger.warning("profile flow replay failed", slug=profile.slug, error=str(exc))

    # 2) Fall back to the saved session snapshot.
    if profile.saved_session and profile.saved_session.get("cookies"):
        logger.info("profile re-auth using saved session fallback",
                    slug=profile.slug, host=host)
        return profile.saved_session

    return None
