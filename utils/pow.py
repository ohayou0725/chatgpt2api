import json
import random
import re
import time
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from typing import Any, Sequence

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


def parse_pow_resources(html_content: str) -> tuple[list[str], str]:
    parser = ScriptSrcParser()
    parser.feed(html_content)
    script_sources = parser.script_sources or [DEFAULT_POW_SCRIPT]
    data_build = parser.data_build
    if not data_build:
        match = re.search(r'<html[^>]*data-build="([^"]*)"', html_content)
        if match:
            data_build = match.group(1)
    return script_sources, data_build


def _legacy_parse_time() -> str:
    now = datetime.now(timezone(timedelta(hours=-5)))
    return now.strftime("%a %b %d %Y %H:%M:%S") + " GMT-0500 (Eastern Standard Time)"


def build_pow_config(
    user_agent: str,
    script_sources: Sequence[str] | None = None,
    data_build: str = "",
) -> list[Any]:
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
    return [
        sum(random.choices(SCREEN_RESOLUTIONS, k=1)[0]),
        _legacy_parse_time(),
        4294705152,
        1,
        user_agent,
        script_source,
        data_build,
        "en-US",
        "en-US,es-US,en,es",
        random.random(),
        navigator_key,
        random.choice(DOCUMENT_KEYS),
        window_key,
        time.perf_counter() * 1000,
        new_uuid(),
        "",
        random.choice(CORES),
        time.time() * 1000 - (time.perf_counter() * 1000),
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
) -> str:
    """名字沿用上游；内容为当前 SDK 的 getRequirementsToken 格式。

    即 "gAAAAAC" + _generateAnswerAsync("wQ8Lk5...", "0") = base64(config) + "~S"。
    求解失败（理论不可达，期望 ~16 次内命中）时退回旧 blocking 格式（纯 base64）。
    """
    config = build_pow_config(user_agent, script_sources=script_sources, data_build=data_build)
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
) -> str:
    config = build_pow_config(user_agent, script_sources=script_sources, data_build=data_build)
    answer = _solve_pow_answer(seed, difficulty, config)
    if answer is None:
        raise RuntimeError(f"failed to solve proof token: difficulty={difficulty}")
    return "gAAAAAB" + answer
