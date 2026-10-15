from __future__ import annotations

import base64
import json
import os
import unittest
from unittest.mock import PropertyMock, patch

os.environ.setdefault("CHATGPT2API_AUTH_KEY", "test-auth")

from curl_cffi import requests as curl_requests

from services.config import config
from services.solver_relay_session import RelayResponse, RelaySession


class FakeRelayHTTPResponse:
    def __init__(self, status_code: int = 200, payload: dict | None = None, text: str = "") -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self) -> dict:
        if self._payload is None:
            raise ValueError("no json payload")
        return self._payload


def relay_reply(status: int = 200, headers: dict | None = None, body: bytes = b"{}",
                url: str = "https://chatgpt.com/x") -> dict:
    return {
        "status": status,
        "headers": headers or {"Content-Type": "application/json"},
        "url": url,
        "body_b64": base64.b64encode(body).decode("ascii"),
    }


class RelaySessionRequestTests(unittest.TestCase):
    """转发会话：构造 /v1/relay 载荷、请求头合并、超时换算、错误处理。"""

    def _session(self, reply: dict | None = None, status_code: int = 200, text: str = ""):
        session = RelaySession("http://solver:8080/", "secret-key")
        calls: list[dict] = []

        def fake_post(url, headers=None, json=None, timeout=None):
            calls.append({"url": url, "headers": headers, "payload": json, "timeout": timeout})
            if reply is None:
                return FakeRelayHTTPResponse(status_code, None, text)
            return FakeRelayHTTPResponse(status_code, reply)

        session._http.post = fake_post
        return session, calls

    def test_get_payload_merges_headers_and_adds_relay_auth(self) -> None:
        session, calls = self._session(relay_reply())
        session.headers.update({"OAI-Device-Id": "dev-1", "X-OpenAI-Target-Path": "/backend-api/me"})

        response = session.get("https://chatgpt.com/backend-api/me",
                               headers={"Accept": "application/json"}, timeout=20)

        self.assertEqual(response.status_code, 200)
        call = calls[0]
        self.assertEqual(call["url"], "http://solver:8080/v1/relay")
        self.assertEqual(call["headers"]["Authorization"], "Bearer secret-key")
        payload = call["payload"]
        self.assertEqual(payload["method"], "GET")
        self.assertEqual(payload["url"], "https://chatgpt.com/backend-api/me")
        self.assertEqual(payload["headers"]["OAI-Device-Id"], "dev-1")
        self.assertEqual(payload["headers"]["Accept"], "application/json")
        self.assertEqual(payload["body_b64"], "")
        # 标量超时（20s）+ 60s 余量，同步传给浏览器侧
        self.assertEqual(payload["timeout_ms"], 80000)
        self.assertEqual(call["timeout"], (15, 80.0))

    def test_json_body_and_content_type(self) -> None:
        session, calls = self._session(relay_reply(body=b'{"ok":true}'))

        response = session.post("https://chatgpt.com/backend-api/sentinel/chat-requirements/prepare",
                                json={"p": "token"}, timeout=30)

        payload = calls[0]["payload"]
        self.assertEqual(json.loads(base64.b64decode(payload["body_b64"])), {"p": "token"})
        self.assertEqual(payload["headers"]["Content-Type"], "application/json")
        self.assertEqual(response.json(), {"ok": True})

    def test_binary_body_passthrough(self) -> None:
        session, calls = self._session(relay_reply(status=201))

        session.put("https://blob.example.com/upload", data=b"\x89PNG\r\n",
                    headers={"Content-Type": "image/png"}, timeout=120)

        payload = calls[0]["payload"]
        self.assertEqual(base64.b64decode(payload["body_b64"]), b"\x89PNG\r\n")

    def test_relay_http_error_raises(self) -> None:
        session, _ = self._session(status_code=503, text="boom")
        with self.assertRaises(RuntimeError):
            session.get("https://chatgpt.com/", timeout=5)

    def test_relay_unreachable_raises(self) -> None:
        session = RelaySession("http://solver:8080", "k")

        def boom(*_args, **_kwargs):
            raise ConnectionError("refused")

        session._http.post = boom
        with self.assertRaises(RuntimeError):
            session.get("https://chatgpt.com/", timeout=5)

    def test_params_appended_to_target(self) -> None:
        session, calls = self._session(relay_reply())
        session.get("https://chatgpt.com/backend-api/models", params={"x": 1}, timeout=10)
        self.assertEqual(calls[0]["payload"]["url"], "https://chatgpt.com/backend-api/models?x=1")


class RelayResponseTests(unittest.TestCase):
    """响应对象：text/json/iter_lines/close 语义与 requests 对齐。"""

    def test_lines_json_and_header_lowercasing(self) -> None:
        response = RelayResponse(200, {"Content-Type": "text/event-stream"},
                                 b"data: a\r\ndata: b\n\n", "https://chatgpt.com/x")
        self.assertEqual(response.headers["content-type"], "text/event-stream")
        self.assertEqual(list(response.iter_lines()), [b"data: a", b"data: b", b""])
        self.assertIn("data: a", response.text)

    def test_close_stops_iteration(self) -> None:
        response = RelayResponse(200, {}, b"a\nb\nc", "u")
        seen = []
        for line in response.iter_lines():
            seen.append(line)
            response.close()
        self.assertEqual(seen, [b"a"])

    def test_json_parses_utf8_content(self) -> None:
        response = RelayResponse(200, {}, '{"msg": "你好"}'.encode("utf-8"), "u")
        self.assertEqual(response.json(), {"msg": "你好"})


class BackendSessionSelectionTests(unittest.TestCase):
    """OpenAIBackendAPI：配置了求解服务走转发会话，否则退回 curl_cffi。"""

    def test_relay_session_when_solver_configured(self) -> None:
        from services import openai_backend_api
        with patch.object(type(config), "sentinel_solver_url", new_callable=PropertyMock,
                          return_value="http://solver:8080"), \
                patch.object(type(config), "sentinel_solver_key", new_callable=PropertyMock,
                             return_value="secret-key"):
            backend = openai_backend_api.OpenAIBackendAPI("")
        try:
            self.assertIsInstance(backend.session, RelaySession)
            self.assertEqual(backend.session.key, "secret-key")
        finally:
            backend.close()

    def test_curl_cffi_session_without_solver(self) -> None:
        from services import openai_backend_api
        with patch.object(type(config), "sentinel_solver_url", new_callable=PropertyMock, return_value=""):
            backend = openai_backend_api.OpenAIBackendAPI("")
        try:
            self.assertIsInstance(backend.session, curl_requests.Session)
        finally:
            backend.close()


if __name__ == "__main__":
    unittest.main()
