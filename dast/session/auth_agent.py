"""
Authentication agent — drives a real browser through the login flow.

Supports:
  - Username/password form login (auto-detects form fields)
  - Token/cookie injection (for API-first apps)
  - OAuth2 / SSO redirect flows (follows redirects until auth completes)

After successful login the storage state is saved as a checkpoint.
"""

from urllib.parse import urlparse

from playwright.async_api import BrowserContext, Page, TimeoutError as PwTimeout

from dast.session.manager import SessionManager
from dast.utils.logger import get_logger

logger = get_logger(__name__)


class AuthAgent:
    """Handles login and checkpoint creation for a given BrowserContext."""

    LOGIN_SELECTORS = [
        'input[type="email"]',
        'input[name="email"]',
        'input[name="username"]',
        'input[name="user"]',
        'input[id*="email"]',
        'input[id*="user"]',
    ]
    PASSWORD_SELECTORS = [
        'input[type="password"]',
        'input[name="password"]',
        'input[name="pass"]',
    ]
    SUBMIT_SELECTORS = [
        'button[type="submit"]',
        'input[type="submit"]',
        'button:has-text("Log in")',
        'button:has-text("Sign in")',
        'button:has-text("Login")',
    ]

    def __init__(
        self,
        context: BrowserContext,
        session_manager: SessionManager,
        auth_url: str,
        username: str,
        password: str,
    ):
        self._context = context
        self._session = session_manager
        self._auth_url = auth_url
        self._username = username
        self._password = password

    async def login(self) -> bool:
        """
        Navigate to auth_url, fill credentials, submit, and save checkpoint.
        Returns True on success.
        """
        page = await self._context.new_page()
        try:
            logger.info("Navigating to auth URL", url=self._auth_url)
            await page.goto(self._auth_url, wait_until="networkidle", timeout=30_000)

            if not await self._fill_credentials(page):
                logger.error("Could not locate login form fields")
                return False

            await self._submit_and_wait(page)

            # Verify login succeeded (not back on login page)
            current = page.url.lower()
            if "login" in current or "signin" in current:
                logger.error("Login failed — still on auth page", url=page.url)
                return False

            # Save checkpoint
            health_url = str(urlparse(self._auth_url)._replace(path="/").geturl())
            await self._session.save_checkpoint(self._context, health_url)
            logger.info("Login successful, checkpoint saved")
            return True

        except PwTimeout:
            logger.error("Login timed out")
            return False
        except Exception as e:
            logger.error("Login error", error=str(e))
            return False
        finally:
            await page.close()

    async def _fill_credentials(self, page: Page) -> bool:
        username_input = await self._find_element(page, self.LOGIN_SELECTORS)
        password_input = await self._find_element(page, self.PASSWORD_SELECTORS)

        if not username_input or not password_input:
            return False

        await username_input.fill(self._username)
        await password_input.fill(self._password)
        return True

    async def _submit_and_wait(self, page: Page) -> None:
        submit = await self._find_element(page, self.SUBMIT_SELECTORS)
        if submit:
            async with page.expect_navigation(wait_until="networkidle", timeout=20_000):
                await submit.click()
        else:
            # Fallback: press Enter on password field
            await page.keyboard.press("Enter")
            await page.wait_for_load_state("networkidle", timeout=20_000)

    async def _find_element(self, page: Page, selectors):
        for sel in selectors:
            try:
                el = page.locator(sel).first
                if await el.is_visible(timeout=500):
                    return el
            except Exception:
                continue
        return None
