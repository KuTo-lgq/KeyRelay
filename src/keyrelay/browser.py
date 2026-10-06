from __future__ import annotations

import asyncio
from pathlib import Path
from urllib.parse import urlparse

from playwright.async_api import async_playwright

from .store import Site


class LoginBroker:
    def __init__(self, profile_dir: Path, *, headless: bool = False):
        self._profile_dir = profile_dir
        self._headless = headless
        self._lock = asyncio.Lock()
        self._playwright = None
        self._context = None

    async def close(self) -> None:
        if self._context:
            await self._context.close()
            self._context = None
        if self._playwright:
            await self._playwright.stop()
            self._playwright = None

    async def login(self, site: Site, credentials: dict[str, str]) -> dict[str, str]:
        async with self._lock:
            await self.close()
            self._playwright = await async_playwright().start()
            try:
                self._context = await self._playwright.chromium.launch_persistent_context(
                    str(self._profile_dir),
                    headless=self._headless,
                    viewport={"width": 1360, "height": 900},
                )
                page = (
                    self._context.pages[0]
                    if self._context.pages
                    else await self._context.new_page()
                )

                async def guard_navigation(route):
                    request = route.request
                    host = (urlparse(request.url).hostname or "").lower()
                    if request.resource_type == "document" and host not in site.allowed_hosts:
                        await route.abort("blockedbyclient")
                    else:
                        await route.continue_()

                await page.route("**/*", guard_navigation)
                await page.goto(site.login_url, wait_until="domcontentloaded", timeout=30_000)
                await page.locator(site.username_selector).fill(credentials["username"])
                await page.locator(site.password_selector).fill(credentials["password"])
                await page.locator(site.submit_selector).click()
                await page.wait_for_load_state("domcontentloaded", timeout=20_000)
                await self._context.storage_state(path=str(self._profile_dir / "session.json"))
                final_url = urlparse(page.url)
                final_host = final_url.hostname or ""
                return {
                    "status": "submitted",
                    "site": site.name,
                    "final_origin": f"{final_url.scheme}://{final_host}",
                    "message": (
                        "登录已提交，浏览器会保持打开。若要求验证码或双重验证，请手动完成。"
                        if final_host in site.allowed_hosts
                        else "导航被安全策略阻止，请检查允许的域名。"
                    ),
                }
            except Exception:
                await self.close()
                raise
