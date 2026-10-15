"""经 sentinel 求解服务的浏览器上下文转发 chatgpt.com 请求。

2026-10-15 起 Cloudflare 对主服务出口的所有非浏览器客户端（curl_cffi 的
chrome110/131/136/142/145/146 等指纹、任何 UA 组合）在敏感路由——首页、
sentinel prepare、conversation init、f/conversation 等——统一下发托管挑战
（403 + cf-mitigated: challenge），只有求解服务里的真实 Chromium 能通过。
因此 OpenAIBackendAPI 把出口会话换成本模块的 RelaySession：请求经求解服务
`/v1/relay` 由浏览器上下文（context.request）代发，浏览器自行补齐 UA、
Client Hints 与 cookie。

两个附带收益：
- 首页 HTML 由浏览器取回，PoW 的脚本清单 / data-build 与真实页面一致；
- 请求 UA 与 sentinel token 里编码的求解页面 UA 完全一致。

注意：转发模式下出口与代理由求解服务浏览器决定（SENTINEL_SOLVER_PROXY），
主服务自身配置的 proxy / clearance 对该出口不生效。
"""
from __future__ import annotations

import base64
import json
from typing import Any, Iterator

from curl_cffi import requests

from utils.log import logger

RELAY_PATH = "/v1/relay"
CONNECT_TIMEOUT_SECONDS = 15
DEFAULT_TIMEOUT_SECONDS = 120.0
READ_SLACK_SECONDS = 60.0
RELAY_TIMEOUT_MAX_MS = 900000


def _encode_json(payload: Any) -> bytes:
    # 独立函数：request(json=...) 的参数名会遮蔽 json 模块
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _read_timeout_seconds(timeout: Any) -> float:
    """把调用方传入的（连接, 读取）超时或标量超时换算成转发读取超时。"""
    if isinstance(timeout, (tuple, list)):
        timeout = timeout[-1] if timeout else None
    try:
        value = float(timeout)
    except (TypeError, ValueError):
        value = DEFAULT_TIMEOUT_SECONDS
    return value + READ_SLACK_SECONDS


class RelayResponse:
    """对齐 curl_cffi / requests Response 在服务端代码里用到的最小面。"""

    def __init__(self, status_code: int, headers: dict[str, str], content: bytes, url: str) -> None:
        self.status_code = int(status_code)
        self.headers = {str(key).lower(): value for key, value in (headers or {}).items()}
        self.content = content or b""
        self.url = url
        self._closed = False

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")

    def json(self, **kwargs: Any) -> Any:
        return json.loads(self.text, **kwargs)

    def iter_lines(self) -> Iterator[bytes]:
        lines = self.content.split(b"\n")
        if lines and lines[-1] == b"":  # 与 requests.iter_lines 对齐：结尾换行不产生空行
            lines.pop()
        for line in lines:
            if self._closed:
                return
            yield line.rstrip(b"\r")

    def close(self) -> None:
        self._closed = True

    def __enter__(self) -> "RelayResponse":
        return self

    def __exit__(self, *exc_info: Any) -> bool:
        self.close()
        return False


class RelaySession:
    """requests.Session 兼容的转发会话：请求交给求解服务的浏览器上下文代发。"""

    def __init__(self, base_url: str, key: str = "") -> None:
        self.base_url = str(base_url).rstrip("/")
        self.key = str(key or "")
        self.headers: dict[str, str] = {}
        self._http = requests.Session()

    def get(self, url: str, **kwargs: Any) -> RelayResponse:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> RelayResponse:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> RelayResponse:
        return self.request("PUT", url, **kwargs)

    def patch(self, url: str, **kwargs: Any) -> RelayResponse:
        return self.request("PATCH", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> RelayResponse:
        return self.request("DELETE", url, **kwargs)

    def request(
            self,
            method: str,
            url: str,
            *,
            headers: dict[str, str] | None = None,
            json: Any = None,
            data: Any = None,
            params: Any = None,
            timeout: Any = None,
            stream: bool = False,
            **_: Any,
    ) -> RelayResponse:
        target = str(url)
        if params:
            from urllib.parse import urlencode
            query = urlencode(params, doseq=True)
            target += ("&" if "?" in target else "?") + query
        merged_headers = dict(self.headers)
        merged_headers.update(headers or {})
        body = b""
        if json is not None:
            body = _encode_json(json)
            if not any(header.lower() == "content-type" for header in merged_headers):
                merged_headers["Content-Type"] = "application/json"
        elif isinstance(data, (bytes, bytearray)):
            body = bytes(data)
        elif data is not None:
            body = str(data).encode("utf-8")
        read_timeout = _read_timeout_seconds(timeout)
        payload = {
            "method": method.upper(),
            "url": target,
            "headers": merged_headers,
            "body_b64": base64.b64encode(body).decode("ascii"),
            "timeout_ms": min(int(read_timeout * 1000), RELAY_TIMEOUT_MAX_MS),
        }
        try:
            response = self._http.post(
                self.base_url + RELAY_PATH,
                headers=self._relay_headers(),
                json=payload,
                timeout=(CONNECT_TIMEOUT_SECONDS, read_timeout),
            )
        except Exception as exc:
            logger.warning({"event": "solver_relay_error", "error": str(exc), "target": target})
            raise RuntimeError(f"solver relay unavailable: {exc}") from exc
        if response.status_code != 200:
            logger.warning({
                "event": "solver_relay_failed",
                "status": response.status_code,
                "body": str(response.text or "")[:200],
                "target": target,
            })
            raise RuntimeError(f"solver relay failed: HTTP {response.status_code}")
        try:
            result = response.json() or {}
            content = base64.b64decode(result.get("body_b64") or "")
        except Exception as exc:
            raise RuntimeError(f"solver relay returned malformed payload: {exc}") from exc
        return RelayResponse(
            result.get("status") or 502,
            result.get("headers") or {},
            content,
            str(result.get("url") or target),
        )

    def close(self) -> None:
        try:
            self._http.close()
        except Exception:
            pass

    def _relay_headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.key:
            headers["Authorization"] = f"Bearer {self.key}"
        return headers
