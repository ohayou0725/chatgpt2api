import json
import random
import re
import time
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from typing import Any, Sequence
from urllib.parse import urljoin

import pybase64

DEFAULT_POW_SCRIPT = "https://chatgpt.com/backend-api/sentinel/sdk.js"
from utils.helper import new_uuid


CORES = [8, 16, 24, 32]
DOCUMENT_KEYS = ["__reactContainer$fzelfjyxej8", "_reactListening5dehydibo78", "location"]
SCREEN_RESOLUTIONS = [[1920, 1080], [1440, 900], [2560, 1440], [3840, 2160]]


class ScriptSrcParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.script_sources: list[str] = []
        self.data_build = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "script":
            return
        attrs_dict = dict(attrs)
        src = attrs_dict.get("src")
        if not src:
            return
        self.script_sources.append(src)
        match = re.search(r"c/[^/]*/_", src)
        if match:
            self.data_build = match.group(0)


def _absolute_script(source: str) -> str:
    """把 HTML 里的相对 script src 还原为绝对 URL。

    网页 SDK 取的是 document.scripts[i].src（DOM 解析后永远是绝对地址），
    直接提交 HTML 里的相对路径与真实页面不一致。
    """
    if source.startswith(("http://", "https://")):
        return source
    if source.startswith("//"):
        return "https:" + source
    return urljoin("https://chatgpt.com/", source)


def parse_pow_resources(html_content: str) -> tuple[list[str], str]:
    parser = ScriptSrcParser()
    parser.feed(html_content)
    script_sources = [_absolute_script(source) for source in parser.script_sources] or [DEFAULT_POW_SCRIPT]
    data_build = parser.data_build
    if not data_build:
        match = re.search(r'<html[^>]*data-build="([^"]*)"', html_content)
        if match:
            data_build = match.group(1)
    return script_sources, data_build


# 网页版 requirements/proof token 的固定字段（Linux Chrome 153 实测值；无求解页面环境时兜底）
DEFAULT_HEAP_LIMIT = 4395630592
DEFAULT_LANGUAGE = "zh-CN"
DEFAULT_LANGUAGES = "en-US,en"


def _browser_date(environment: dict[str, Any]) -> str:
    """复刻浏览器 `new Date().toString()`；有求解页面环境时用它的时区，否则用本机时区。"""
    suffix = str(environment.get("date_suffix") or "")
    offset = environment.get("utc_offset_minutes")
    if suffix and isinstance(offset, (int, float)):
        now = datetime.now(timezone(timedelta(minutes=int(offset))))
    else:
        now = datetime.now().astimezone()
        suffix = f"GMT{now.strftime('%z')} ({now.tzname()})"
    return now.strftime("%a %b %d %Y %H:%M:%S") + " " + suffix


def build_pow_config(
    user_agent: str,
    script_sources: Sequence[str] | None = None,
    data_build: str = "",
    environment: dict[str, Any] | None = None,
) -> list[Any]:
    """按网页 sentinel SDK 的 25 字段格式生成浏览器指纹。

    时区、语言、核数等优先取求解页面的真实值（见 sentinel_solver /health 的 environment），
    与算 Turnstile 的页面保持一致；旧版写死美东时区、en-US 等值的组合会被判为低质量请求。
    """
    environment = environment or {}
    navigator_key = random.choice([
        "registerProtocolHandler−function registerProtocolHandler() { [native code] }",
        "storage−[object StorageManager]",
        "locks−[object LockManager]",
        "appCodeName−Mozilla",
        "permissions−[object Permissions]",
        "share−function share() { [native code] }",
        "webdriver−false",
        "managed−[object NavigatorManagedData]",
        "canShare−function canShare() { [native code] }",
        "vendor−Google Inc.",
        "mediaDevices−[object MediaDevices]",
        "vibrate−function vibrate() { [native code] }",
        "storageBuckets−[object StorageBucketManager]",
        "mediaCapabilities−[object MediaCapabilities]",
        "cookieEnabled−true",
        "virtualKeyboard−[object VirtualKeyboard]",
        "product−Gecko",
        "presentation−[object Presentation]",
        "onLine−true",
        "mimeTypes−[object MimeTypeArray]",
        "credentials−[object CredentialsContainer]",
        "serviceWorker−[object ServiceWorkerContainer]",
        "keyboard−[object Keyboard]",
        "gpu−[object GPU]",
        "doNotTrack",
        "serial−[object Serial]",
        "pdfViewerEnabled−true",
        "language−zh-CN",
        "geolocation−[object Geolocation]",
        "userAgentData−[object NavigatorUAData]",
        "getUserMedia−function getUserMedia() { [native code] }",
        "sendBeacon−function sendBeacon() { [native code] }",
        "hardwareConcurrency−32",
        "windowControlsOverlay−[object WindowControlsOverlay]",
    ])
    window_key = random.choice([
        "0",
        "window",
        "self",
        "document",
        "name",
        "location",
        "customElements",
        "history",
        "navigation",
        "innerWidth",
        "innerHeight",
        "scrollX",
        "scrollY",
        "visualViewport",
        "screenX",
        "screenY",
        "outerWidth",
        "outerHeight",
        "devicePixelRatio",
        "screen",
        "chrome",
        "navigator",
        "onresize",
        "performance",
        "crypto",
        "indexedDB",
        "sessionStorage",
        "localStorage",
        "scheduler",
        "alert",
        "atob",
        "btoa",
        "fetch",
        "matchMedia",
        "postMessage",
        "queueMicrotask",
        "requestAnimationFrame",
        "setInterval",
        "setTimeout",
        "caches",
        "__NEXT_DATA__",
        "__BUILD_MANIFEST",
        "__NEXT_PRELOADREADY",
    ])
    script_source = random.choice(list(script_sources)) if script_sources else DEFAULT_POW_SCRIPT
    # 页面打开以来的毫秒数；旧版用 time.perf_counter()，在 Linux 上是开机时长，明显不像真实页面
    page_age_ms = random.uniform(2000, 30000)
    return [
        int(environment.get("screen_sum") or sum(random.choice(SCREEN_RESOLUTIONS))),
        _browser_date(environment),
        int(environment.get("heap_limit") or DEFAULT_HEAP_LIMIT),
        1,
        user_agent,
        script_source,
        data_build,
        str(environment.get("language") or DEFAULT_LANGUAGE),
        str(environment.get("languages") or DEFAULT_LANGUAGES),
        random.random(),
        navigator_key,
        random.choice(DOCUMENT_KEYS),
        window_key,
        page_age_ms,
        new_uuid(),
        "",
        int(environment.get("hardware_concurrency") or random.choice(CORES)),
        time.time() * 1000 - page_age_ms,
        0, 0, 0, 0, 0, 0,
        0,  # 0 = edge/chrome, 1 = firefox
    ]


POW_REQUIREMENTS_SEED = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"
POW_ANSWER_SUFFIX = "~S"
POW_MAX_ATTEMPTS = 500000
_FNV_OFFSET_BASIS = 2166136261
_FNV_PRIME = 16777619


def _fnv1a_avalanche(value: str) -> str:
    """sentinel SDK（2026-10-14 版）的 PoW 摘要：FNV-1a 32 位 + murmur3 fmix32 终混。

    对应 sdk.js 里 `let e=2166136261; for(...) e^=t.charCodeAt(r), e=Math.imul(e,16777619)>>>0;`
    之后的三步终混；charCodeAt 是 UTF-16 码元语义，因此按 utf-16-le 逐码元迭代。
    """
    digest = _FNV_OFFSET_BASIS
    units = value.encode("utf-16-le")
    for index in range(0, len(units), 2):
        digest ^= units[index] | (units[index + 1] << 8)
        digest = (digest * _FNV_PRIME) & 0xFFFFFFFF
    digest ^= digest >> 16
    digest = (digest * 2246822507) & 0xFFFFFFFF
    digest ^= digest >> 13
    digest = (digest * 3266489909) & 0xFFFFFFFF
    digest ^= digest >> 16
    return f"{digest:08x}"


def _encode_pow_config(config: list[Any]) -> str:
    # 对应 sdk.js 的 N()：btoa(TextEncoder(JSON.stringify(config)))
    return pybase64.b64encode(
        json.dumps(config, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).decode()


def _solve_pow_answer(
    seed: str,
    difficulty: str,
    config: list[Any],
    limit: int = POW_MAX_ATTEMPTS,
) -> str | None:
    """按 sdk.js 的 _generateAnswerAsync/_runCheck 逐次尝试。

    每次把 [3] 置为尝试序号、[9] 置为求解耗时（毫秒），
    摘要前缀 `<= difficulty`（与 JS 相同的字符串比较）时返回 base64 + "~S"。
    """
    working = list(config)
    difficulty_length = len(difficulty)
    started = time.perf_counter()
    for attempt in range(limit):
        working[3] = attempt
        working[9] = int((time.perf_counter() - started) * 1000 + 0.5)  # Math.round
        encoded = _encode_pow_config(working)
        if _fnv1a_avalanche(seed + encoded)[:difficulty_length] <= difficulty:
            return encoded + POW_ANSWER_SUFFIX
    return None


def build_legacy_requirements_token(
    user_agent: str,
    script_sources: Sequence[str] | None = None,
    data_build: str = "",
    environment: dict[str, Any] | None = None,
) -> str:
    """名字沿用上游；内容为当前 SDK 的 getRequirementsToken 格式。

    即 "gAAAAAC" + _generateAnswerAsync("wQ8Lk5...", "0") = base64(config) + "~S"。
    求解失败（理论不可达，期望 ~16 次内命中）时退回旧 blocking 格式（纯 base64）。
    """
    config = build_pow_config(user_agent, script_sources=script_sources, data_build=data_build, environment=environment)
    answer = _solve_pow_answer(POW_REQUIREMENTS_SEED, "0", config)
    if answer is None:
        answer = _encode_pow_config(config)
    return "gAAAAAC" + answer


def build_proof_token(
    seed: str,
    difficulty: str,
    user_agent: str,
    script_sources: Sequence[str] | None = None,
    data_build: str = "",
    environment: dict[str, Any] | None = None,
) -> str:
    config = build_pow_config(user_agent, script_sources=script_sources, data_build=data_build, environment=environment)
    answer = _solve_pow_answer(seed, difficulty, config)
    if answer is None:
        raise RuntimeError(f"failed to solve proof token: difficulty={difficulty}")
    return "gAAAAAB" + answer
