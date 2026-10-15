"""sentinel 求解服务：常驻一个无头 Chrome 的 chatgpt.com 页面，替主服务完成两件事。

1. 计算 Turnstile / SO token（2026-10-14 起对话接口要求 token 出自真实页面）。
2. 转发主服务发往 chatgpt.com 的 HTTP 请求（`/v1/relay`）——2026-10-15 起
   Cloudflare 对主服务出口的所有非浏览器客户端在敏感路由（首页、sentinel
   prepare、conversation init 等）统一下发托管挑战，curl_cffi 任何指纹都无法
   通过，只有真实 Chromium 可以，因此由本服务的浏览器上下文代发请求。

环境变量：
- SENTINEL_SOLVER_KEY：可选，设置后请求需带 `Authorization: Bearer <key>`
- SENTINEL_SOLVER_PROXY：可选，浏览器出网代理（如 http://host:7890），应与主服务出口一致
- SENTINEL_SOLVER_USER_AGENT：可选，默认按内置 Chromium 版本生成 Linux Chrome UA
- SENTINEL_SOLVER_TIMEZONE：可选，页面时区（如 Asia/Tokyo），应与出口 IP 所在地一致；默认跟随系统
- SENTINEL_SOLVER_REFRESH_SECONDS：页面定期重开的间隔，默认 1800
- SENTINEL_SOLVER_HEADLESS：默认 true；调试时可设为 false
- PORT：监听端口，默认 8080
"""
from __future__ import annotations

import asyncio
import base64
import hmac
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse

import uvicorn
from fastapi import FastAPI, Header, HTTPException
from playwright.async_api import Browser, BrowserContext, Page, Playwright, async_playwright
from playwright_stealth import Stealth
from pydantic import BaseModel

CHATGPT_URL = "https://chatgpt.com/"
CHALLENGE_TITLES = ("请稍候", "Just a moment", "Attention Required")
VM_SCRIPT = (Path(__file__).parent / "vm.js").read_text(encoding="utf-8")
BASE_INIT_SCRIPT = """
Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
window.chrome = window.chrome || { runtime: {} };
"""

SOLVER_KEY = os.getenv("SENTINEL_SOLVER_KEY", "").strip()
PROXY = os.getenv("SENTINEL_SOLVER_PROXY", "").strip()
USER_AGENT = os.getenv("SENTINEL_SOLVER_USER_AGENT", "").strip()
TIMEZONE = os.getenv("SENTINEL_SOLVER_TIMEZONE", "").strip()
REFRESH_SECONDS = max(60, int(os.getenv("SENTINEL_SOLVER_REFRESH_SECONDS", "1800")))
HEADLESS = os.getenv("SENTINEL_SOLVER_HEADLESS", "true").strip().lower() not in {"0", "false", "no"}
READY_TIMEOUT_SECONDS = 60

# 转发时丢弃的请求头：传输层细节，以及必须由浏览器自己补齐的指纹类头
DROP_REQUEST_HEADERS = {
    "host", "content-length", "connection", "keep-alive", "transfer-encoding", "te", "trailer",
    "upgrade", "accept-encoding", "cookie", "user-agent",
    "sec-ch-ua", "sec-ch-ua-arch", "sec-ch-ua-bitness", "sec-ch-ua-full-version",
    "sec-ch-ua-full-version-list", "sec-ch-ua-mobile", "sec-ch-ua-model",
    "sec-ch-ua-platform", "sec-ch-ua-platform-version",
}
# 转发时丢弃的响应头：由浏览器解码处理过，回传会造成双重解码
DROP_RESPONSE_HEADERS = {
    "content-encoding", "content-length", "transfer-encoding", "connection", "set-cookie", "set-cookie2",
}
RELAY_TIMEOUT_MIN_MS = 5000
RELAY_TIMEOUT_MAX_MS = 900000


class SolverPage:
    """维护一个已通过 Cloudflare 校验的 chatgpt.com 页面，按需重开。"""

    def __init__(self) -> None:
        self._playwright: Playwright | None = None
        self._browser: Browser | None = None
        self._context: BrowserContext | None = None
        self._page: Page | None = None
        self._opened_at = 0.0
        self._lock = asyncio.Lock()
        self.user_agent = USER_AGENT
        self.last_error = ""

    async def start(self) -> None:
        self._playwright = await async_playwright().start()
        launch_kwargs = {
            "headless": HEADLESS,
            # channel="chromium" 使用完整 Chromium 的新版无头模式；默认的 headless shell 过不了 Cloudflare
            "channel": "chromium",
            "args": ["--disable-blink-features=AutomationControlled", "--no-sandbox", "--disable-dev-shm-usage"],
        }
        if PROXY:
            launch_kwargs["proxy"] = {"server": PROXY}
        self._browser = await self._playwright.chromium.launch(**launch_kwargs)
        if not self.user_agent:
            major = self._browser.version.split(".")[0]
            self.user_agent = (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                f"(KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36"
            )
        try:
            await self.page()
        except Exception as exc:  # 启动时页面暂时打不开不致命，首个请求会重试
            self.last_error = str(exc)
            print(f"[sentinel-solver] initial page open failed: {exc}", flush=True)

    async def stop(self) -> None:
        if self._context is not None:
            await self._context.close()
        if self._browser is not None:
            await self._browser.close()
        if self._playwright is not None:
            await self._playwright.stop()

    async def page(self) -> Page:
        async with self._lock:
            stale = self._page is None or time.monotonic() - self._opened_at > REFRESH_SECONDS
            if not stale and not await self._is_ready(self._page):
                stale = True
            if stale:
                await self._reopen()
            return self._page

    async def invalidate(self) -> None:
        async with self._lock:
            self._opened_at = 0.0

    async def _reopen(self) -> None:
        if self._context is not None:
            try:
                await self._context.close()
            except Exception:
                pass
        self._page = None
        context_kwargs = {
            "locale": "zh-CN",
            "viewport": {"width": 1280, "height": 800},
            "user_agent": self.user_agent,
        }
        if TIMEZONE:
            context_kwargs["timezone_id"] = TIMEZONE
        context = await self._browser.new_context(**context_kwargs)
        await context.add_init_script(BASE_INIT_SCRIPT)
        await context.add_init_script(VM_SCRIPT)
        await Stealth().apply_stealth_async(context)
        page = await context.new_page()
        await page.goto(CHATGPT_URL, wait_until="domcontentloaded", timeout=60000)
        deadline = time.monotonic() + READY_TIMEOUT_SECONDS
        while not await self._is_ready(page):
            if time.monotonic() > deadline:
                title = await page.title()
                await context.close()
                raise RuntimeError(f"chatgpt.com page not ready (title={title!r}), likely stuck on a Cloudflare challenge")
            await asyncio.sleep(1)
        self._context = context
        self._page = page
        self._opened_at = time.monotonic()
        self.last_error = ""
        print(f"[sentinel-solver] chatgpt.com page ready: {await page.title()!r}", flush=True)

    @staticmethod
    async def _is_ready(page: Page | None) -> bool:
        if page is None or page.is_closed():
            return False
        try:
            title = await page.title()
            if any(marker in title for marker in CHALLENGE_TITLES):
                return False
            return await page.evaluate("location.hostname === 'chatgpt.com' && typeof window.__sentinelVM === 'object'")
        except Exception:
            return False

    async def evaluate(self, expression: str, arg: object) -> object:
        """在页面里执行；页面失效时重开一次再试。"""
        for attempt in range(2):
            page = await self.page()
            try:
                return await page.evaluate(expression, arg)
            except Exception as exc:
                self.last_error = str(exc)
                if attempt:
                    raise
                await self.invalidate()
        raise RuntimeError("unreachable")

    def status(self) -> dict[str, object]:
        return {
            "ready": self._page is not None and not self._page.is_closed(),
            "page_age_seconds": int(time.monotonic() - self._opened_at) if self._opened_at else None,
            "browser_version": self._browser.version if self._browser else None,
            "user_agent": self.user_agent,
            "timezone": TIMEZONE or None,
            "last_error": self.last_error or None,
        }


solver = SolverPage()


@asynccontextmanager
async def lifespan(_: FastAPI):
    await solver.start()
    yield
    await solver.stop()


app = FastAPI(title="chatgpt2api sentinel solver", lifespan=lifespan)


class TurnstileRequest(BaseModel):
    dx: str
    p: str


class SORequest(BaseModel):
    collector_dx: str
    snapshot_dx: str
    p: str


class RelayRequest(BaseModel):
    method: str = "GET"
    url: str
    headers: dict[str, str] = {}
    body_b64: str = ""
    timeout_ms: int = 300000


def require_key(authorization: str | None) -> None:
    if not SOLVER_KEY:
        return
    supplied = (authorization or "").removeprefix("Bearer ").strip()
    if not hmac.compare_digest(supplied, SOLVER_KEY):
        raise HTTPException(status_code=401, detail="invalid solver key")


def _is_forbidden_host(host: str) -> bool:
    """转发只允许公网 https；挡掉本机/内网/元数据地址，避免变成内网探针。"""
    name = host.lower().strip("[]")
    if name in {"localhost", "metadata.google.internal"} or name.endswith((".local", ".internal", ".localhost")):
        return True
    parts = name.split(".")
    if len(parts) == 4 and all(part.isdigit() for part in parts):
        first, second = int(parts[0]), int(parts[1])
        return (
            first in {0, 10, 127}
            or (first == 169 and second == 254)
            or (first == 172 and 16 <= second <= 31)
            or (first == 192 and second == 168)
        )
    return False


async def _relay_fetch(page: Page, method: str, url: str, headers: dict[str, str], payload: bytes | None,
                       timeout_ms: int):
    kwargs: dict[str, object] = {"method": method, "timeout": timeout_ms, "fail_on_status_code": False}
    if headers:
        kwargs["headers"] = headers
    if payload is not None:
        kwargs["data"] = payload
    return await page.context.request.fetch(url, **kwargs)


@app.get("/health")
async def health() -> dict[str, object]:
    return solver.status()


@app.get("/v1/cookies")
async def get_cookies(authorization: str | None = Header(default=None)) -> dict[str, object]:
    """返回求解页面当前持有的 chatgpt.com cookie 与浏览器指纹（诊断用）。

    本服务只输出求解页面自己的浏览器状态，不接收也不返回任何账号数据。
    """
    require_key(authorization)
    try:
        page = await solver.page()
        cookies = await page.context.cookies("https://chatgpt.com/")
        client_hints = await page.evaluate(
            """async () => {
                const data = navigator.userAgentData;
                if (!data) return {};
                const high = await data.getHighEntropyValues(
                    ["architecture", "bitness", "fullVersionList", "platformVersion"]
                ).catch(() => ({}));
                return {
                    brands: data.brands,
                    mobile: data.mobile,
                    platform: data.platform,
                    architecture: high.architecture || "",
                    bitness: high.bitness || "",
                    platformVersion: high.platformVersion || "",
                    fullVersionList: high.fullVersionList || [],
                };
            }"""
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"cookie fetch failed: {exc}") from exc
    return {"cookies": cookies, "user_agent": solver.user_agent, "client_hints": client_hints}


@app.post("/v1/turnstile")
async def solve_turnstile(body: TurnstileRequest, authorization: str | None = Header(default=None)) -> dict[str, str]:
    require_key(authorization)
    try:
        token = await solver.evaluate("([dx, p]) => window.__sentinelVM.turnstile(dx, p)", [body.dx, body.p])
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"turnstile solve failed: {exc}") from exc
    return {"token": str(token or "")}


@app.post("/v1/so")
async def solve_so(body: SORequest, authorization: str | None = Header(default=None)) -> dict[str, str]:
    require_key(authorization)
    try:
        token = await solver.evaluate(
            "([c, s, p]) => window.__sentinelVM.so(c, s, p)", [body.collector_dx, body.snapshot_dx, body.p]
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"so solve failed: {exc}") from exc
    return {"token": str(token or "")}


@app.post("/v1/relay")
async def relay(body: RelayRequest, authorization: str | None = Header(default=None)) -> dict[str, object]:
    """用浏览器上下文代发一个 HTTP 请求（主服务唯一能通过 Cloudflare 的出口）。

    浏览器自动补齐 UA / Client Hints / cookie；若浏览器自身吃到 CF 挑战
    （例如页面上的校验过期），重开一次页面后重试一遍。
    """
    require_key(authorization)
    parsed = urlparse(str(body.url or "").strip())
    if parsed.scheme != "https" or not parsed.hostname or _is_forbidden_host(parsed.hostname):
        raise HTTPException(status_code=400, detail="url not allowed")
    method = (body.method or "GET").upper()
    headers = {k: v for k, v in (body.headers or {}).items() if k.lower() not in DROP_REQUEST_HEADERS}
    payload = base64.b64decode(body.body_b64) if body.body_b64 else None
    timeout_ms = max(RELAY_TIMEOUT_MIN_MS, min(int(body.timeout_ms or 300000), RELAY_TIMEOUT_MAX_MS))
    try:
        page = await solver.page()
        response = await _relay_fetch(page, method, body.url, headers, payload, timeout_ms)
        if response.status == 403 and str((response.headers or {}).get("cf-mitigated") or "") == "challenge":
            await solver.invalidate()
            page = await solver.page()
            response = await _relay_fetch(page, method, body.url, headers, payload, timeout_ms)
        raw = await response.body()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"relay failed: {exc}") from exc
    response_headers = {k: v for k, v in (response.headers or {}).items() if k.lower() not in DROP_RESPONSE_HEADERS}
    return {
        "status": response.status,
        "headers": response_headers,
        "url": response.url,
        "body_b64": base64.b64encode(raw).decode("ascii"),
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8080")), access_log=False)
