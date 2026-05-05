"""
modules/ninja.py
Advanced Stealth, Proxy Rotation, and CAPTCHA evasion for CREEPER.
Provides proxy management and Playwright stealth injection.
"""

import asyncio
import logging
import random
from typing import List, Optional

logger = logging.getLogger("CREEPER.ninja")

class NinjaStealth:
    """
    Manages proxy rotation and advanced stealth mechanisms.
    """

    def __init__(self, proxies: Optional[List[str]] = None, use_ninja_mode: bool = False):
        self.proxies = [p.strip() for p in proxies if p.strip()] if proxies else []
        self.use_ninja_mode = use_ninja_mode
        self._proxy_index = 0

    def get_proxy(self) -> Optional[str]:
        """Returns the next proxy in a round-robin fashion."""
        if not self.proxies:
            return None
        proxy = self.proxies[self._proxy_index]
        self._proxy_index = (self._proxy_index + 1) % len(self.proxies)
        return proxy

    async def apply_playwright_stealth(self, page) -> None:
        """
        Injects stealth scripts into a Playwright page to evade basic bot detection.
        (e.g., removing navigator.webdriver, mocking languages, plugins).
        """
        if not self.use_ninja_mode:
            return
            
        stealth_scripts = [
            # Pass webdriver check
            "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})",
            # Pass generic plugin checks
            "Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3]})",
            "Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']})",
            # Mock chrome object
            "window.chrome = { runtime: {} }",
            # Pass permissions check
            """
            const originalQuery = window.navigator.permissions.query;
            return window.navigator.permissions.query = (parameters) => (
                parameters.name === 'notifications' ?
                    Promise.resolve({ state: Notification.permission }) :
                    originalQuery(parameters)
            );
            """
        ]
        
        for script in stealth_scripts:
            try:
                await page.add_init_script(script)
            except Exception as e:
                logger.debug(f"Failed to inject stealth script: {e}")
                
    def get_aiohttp_kwargs(self) -> dict:
        """Returns kwargs (like proxy) to be passed to aiohttp.ClientSession.get"""
        kwargs = {}
        proxy = self.get_proxy()
        if proxy:
            # aiohttp expects proxy as a string URL
            if not proxy.startswith('http'):
                proxy = f"http://{proxy}"
            kwargs['proxy'] = proxy
        return kwargs
