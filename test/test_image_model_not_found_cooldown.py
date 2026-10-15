from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("CHATGPT2API_AUTH_KEY", "test-auth")

from services.account_service import AccountService
from services.protocol import conversation
from services.protocol.conversation import ImageGenerationError, ImageOutput
from services.storage.json_storage import JSONStorageBackend
from utils.helper import UpstreamHTTPError


def disguised_model_not_found() -> UpstreamHTTPError:
    return UpstreamHTTPError("/backend-api/f/conversation", 404, {"detail": "Model not found"})


class FakeBackend:
    def __init__(self, access_token: str = "") -> None:
        self.access_token = access_token
        self.closed = False

    def close(self) -> None:
        self.closed = True


class ModelNotFoundPredicateTests(unittest.TestCase):
    """伪装 404 谓词：只有「404 + detail 精确等于 Model not found」才命中。"""

    def test_exact_disguised_404_matches(self) -> None:
        self.assertTrue(conversation.is_upstream_model_not_found_error(disguised_model_not_found()))

    def test_other_shapes_do_not_match(self) -> None:
        cases = [
            UpstreamHTTPError("/backend-api/f/conversation", 404, {"detail": "Other detail"}),
            UpstreamHTTPError("/backend-api/f/conversation", 500, {"detail": "Model not found"}),
            UpstreamHTTPError("/backend-api/f/conversation", 404, "Model not found"),
            UpstreamHTTPError("/backend-api/f/conversation", 404, {}),
            UpstreamHTTPError("/backend-api/f/conversation", 404, None),
            RuntimeError("Model not found"),
            Exception("status=404, body={'detail': 'Model not found'}"),
        ]
        for exc in cases:
            self.assertFalse(conversation.is_upstream_model_not_found_error(exc), msg=repr(exc))


class ModelNotFoundRetryTests(unittest.TestCase):
    """_generate_single_image 遇到伪装 404 时：冷却失败账号并换号重试。"""

    def _request(self) -> conversation.ConversationRequest:
        return conversation.ConversationRequest(model="gpt-image-2", prompt="a cat")

    def _run(self, tokens: list[str], stream_side_effect: list):
        cooldowns: list[tuple[str, int | None]] = []
        marked: list[tuple[str, bool]] = []
        issued = list(tokens)
        lookup: list[str] = []

        def fake_get_token(*_args, **_kwargs) -> str:
            self.assertTrue(issued, "get_available_access_token 调用次数超出预期")
            token = issued.pop(0)
            lookup.append(token)
            return token

        def fake_mark_cooldown(token, *, event="", seconds=None) -> str:
            cooldowns.append((token, seconds))
            return "2026-10-15T12:10:00+00:00"

        with patch.object(conversation, "OpenAIBackendAPI", FakeBackend), \
                patch.object(conversation, "stream_image_outputs", side_effect=stream_side_effect), \
                patch.object(conversation.account_service, "get_available_access_token",
                             side_effect=fake_get_token), \
                patch.object(conversation.account_service, "get_account",
                             side_effect=lambda token: {"email": f"{token}@example.com"}), \
                patch.object(conversation.account_service, "mark_image_result",
                             side_effect=lambda token, success: marked.append((token, success))), \
                patch.object(conversation.account_service, "mark_image_cooldown",
                             side_effect=fake_mark_cooldown):
            with self.assertRaises(ImageGenerationError) as ctx:
                conversation._generate_single_image(self._request(), 1, 1)
        return ctx.exception, cooldowns, marked, lookup

    def test_exhausted_retries_cool_down_each_failed_account(self) -> None:
        error, cooldowns, marked, lookup = self._run(
            ["tok-1", "tok-2", "tok-3", "tok-4"],
            [disguised_model_not_found()] * 4,
        )
        # 4 次尝试（首次 + 3 次重试），每次失败账号都被冷却
        self.assertEqual(lookup, ["tok-1", "tok-2", "tok-3", "tok-4"])
        self.assertEqual([item[0] for item in cooldowns], ["tok-1", "tok-2", "tok-3", "tok-4"])
        self.assertEqual(marked, [("tok-1", False), ("tok-2", False), ("tok-3", False), ("tok-4", False)])
        self.assertEqual(error.status_code, 502)
        self.assertEqual(error.code, "upstream_model_not_found")
        # 对外错误文案不泄露上游细节
        self.assertNotIn("backend-api/", str(error))
        self.assertNotIn("status=", str(error))

    def test_switches_account_and_succeeds(self) -> None:
        success_output = ImageOutput(kind="result", model="gpt-image-2", index=1, total=1,
                                     data=[{"b64_json": "aGVsbG8="}])
        outputs_box: dict = {}

        def fake_stream(backend, request, index, total):
            if not outputs_box:
                outputs_box["first"] = True
                raise disguised_model_not_found()
            return iter([success_output])

        cooldowns: list[str] = []
        marked: list[tuple[str, bool]] = []
        issued = ["tok-1", "tok-2"]

        with patch.object(conversation, "OpenAIBackendAPI", FakeBackend), \
                patch.object(conversation, "stream_image_outputs", side_effect=fake_stream), \
                patch.object(conversation.account_service, "get_available_access_token",
                             side_effect=lambda *_a, **_k: issued.pop(0)), \
                patch.object(conversation.account_service, "get_account",
                             side_effect=lambda token: {"email": f"{token}@example.com"}), \
                patch.object(conversation.account_service, "mark_image_result",
                             side_effect=lambda token, success: marked.append((token, success))), \
                patch.object(conversation.account_service, "mark_image_cooldown",
                             side_effect=lambda token, **kw: cooldowns.append(token) or "2026-10-15T12:10:00+00:00"):
            outputs = conversation._generate_single_image(self._request(), 1, 1)

        self.assertEqual([output.kind for output in outputs], ["result"])
        self.assertEqual(cooldowns, ["tok-1"])
        self.assertEqual(marked, [("tok-1", False), ("tok-2", True)])

    def test_other_404_does_not_cool_down_or_switch_account(self) -> None:
        other_404 = UpstreamHTTPError("/backend-api/f/conversation", 404, {"detail": "Not Found"})
        error, cooldowns, marked, lookup = self._run(["tok-1"], [other_404])
        self.assertEqual(lookup, ["tok-1"])
        self.assertEqual(cooldowns, [])
        self.assertEqual(marked, [("tok-1", False)])
        self.assertNotEqual(error.code, "upstream_model_not_found")


class ImageCooldownAccountTests(unittest.TestCase):
    """账号冷却字段：持久化、过滤、且不影响额度/状态。"""

    def _service(self, tmp_dir: str) -> AccountService:
        service = AccountService(JSONStorageBackend(Path(tmp_dir) / "accounts.json"))
        service.add_accounts(["token-1"])
        service.update_account("token-1", {"status": "正常", "quota": 3, "fail": 1, "email": "a@example.com"})
        return service

    def test_mark_cooldown_persists_and_excludes_account(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            service = self._service(tmp_dir)
            cooldown_until = service.mark_image_cooldown("token-1", event="image_stream", seconds=600)

            self.assertTrue(cooldown_until)
            parsed = datetime.fromisoformat(cooldown_until)
            self.assertGreater(parsed, datetime.now(timezone.utc) + timedelta(seconds=540))

            account = service.get_account("token-1")
            self.assertEqual(account.get("image_cooldown_until"), cooldown_until)
            # 只写冷却字段：额度、状态、失败计数都不变
            self.assertEqual(account.get("quota"), 3)
            self.assertEqual(account.get("status"), "正常")
            self.assertEqual(account.get("fail"), 1)
            self.assertFalse(AccountService._is_image_account_available(account))

            # 重启后字段仍在（走 storage 重新加载）
            reloaded = AccountService(JSONStorageBackend(Path(tmp_dir) / "accounts.json"))
            self.assertEqual(reloaded.get_account("token-1").get("image_cooldown_until"), cooldown_until)

    def test_expired_cooldown_allows_account_again(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            service = self._service(tmp_dir)
            expired = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
            service.update_account("token-1", {"image_cooldown_until": expired})

            account = service.get_account("token-1")
            self.assertTrue(AccountService._is_image_account_available(account))


if __name__ == "__main__":
    unittest.main()
