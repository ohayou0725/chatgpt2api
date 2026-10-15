from __future__ import annotations

import json
import unittest
from unittest.mock import patch

import pybase64

from utils import pow as pow_module
from utils.pow import (
    POW_ANSWER_SUFFIX,
    POW_REQUIREMENTS_SEED,
    _fnv1a_avalanche,
    _solve_pow_answer,
    build_legacy_requirements_token,
    build_pow_config,
    build_proof_token,
)


class DigestVectorTests(unittest.TestCase):
    """摘要函数：向量取自官方 sdk.js 逐字实现（node 跑真机代码得出）。"""

    def test_known_vectors(self) -> None:
        for value, expected in [
            ("", "ab3e7c0b"),
            ("hello", "888d766e"),
            (POW_REQUIREMENTS_SEED + "abc", "ec6b1e79"),
            ("A−B", "c6a10881"),    # U+2212，多字节 UTF-8 路径
            ("\U00010348", "40c1f718"),  # 代理对：验证 UTF-16 码元语义
        ]:
            self.assertEqual(_fnv1a_avalanche(value), expected, repr(value))

    def test_digest_shape(self) -> None:
        self.assertRegex(_fnv1a_avalanche("x" * 4096), r"^[0-9a-f]{8}$")


class SolveAnswerTests(unittest.TestCase):
    """求解循环：字段语义、难度比较、失败处理与"~S"后缀。"""

    def _config(self) -> list:
        return build_pow_config("Mozilla/5.0 (X11; Linux x86_64) Chrome/146.0.0.0")

    def _payload(self, answer: str) -> list:
        self.assertTrue(answer.endswith(POW_ANSWER_SUFFIX))
        return json.loads(pybase64.b64decode(answer[: -len(POW_ANSWER_SUFFIX)]))

    def test_difficulty_zero_solution(self) -> None:
        answer = _solve_pow_answer(POW_REQUIREMENTS_SEED, "0", self._config())
        self.assertIsNotNone(answer)
        encoded = answer[: -len(POW_ANSWER_SUFFIX)]
        self.assertLessEqual(_fnv1a_avalanche(POW_REQUIREMENTS_SEED + encoded)[:1], "0")
        payload = self._payload(answer)
        self.assertIsInstance(payload[3], int)
        self.assertIsInstance(payload[9], int)

    def test_attempt_index_increments_until_hit(self) -> None:
        seen: list[str] = []

        def fake_digest(value: str) -> str:
            seen.append(value)
            return "00" if len(seen) >= 3 else "ff"

        with patch.object(pow_module, "_fnv1a_avalanche", fake_digest):
            answer = _solve_pow_answer("seed", "00", self._config())
        self.assertEqual(self._payload(answer)[3], 2)  # 第三次尝试命中

    def test_empty_difficulty_hits_first_attempt(self) -> None:
        answer = _solve_pow_answer("seed", "", self._config())
        self.assertEqual(self._payload(answer)[3], 0)

    def test_gives_up_after_limit(self) -> None:
        self.assertIsNone(_solve_pow_answer("seed", "00000000", self._config(), limit=5))


class EnvironmentConfigTests(unittest.TestCase):
    """求解页面环境（时区/语言/核数等）应驱动 25 字段指纹，而不是兜底值。"""

    ENVIRONMENT = {
        "screen_sum": 2080,
        "date_suffix": "GMT+0800 (中国标准时间)",
        "utc_offset_minutes": 480,
        "heap_limit": 4395630592,
        "language": "zh-CN",
        "languages": "en-US,en",
        "hardware_concurrency": 28,
    }

    def test_config_uses_solver_environment(self) -> None:
        fields = build_pow_config("UA/1", ["https://chatgpt.com/a.js"], "build", self.ENVIRONMENT)
        self.assertEqual(len(fields), 25)
        self.assertEqual(fields[0], 2080)
        self.assertTrue(fields[1].endswith("GMT+0800 (中国标准时间)"))
        self.assertEqual(fields[2], 4395630592)
        self.assertEqual(fields[7:9], ["zh-CN", "en-US,en"])
        self.assertEqual(fields[16], 28)
        self.assertLess(fields[13], 60000)

    def test_config_without_environment_falls_back(self) -> None:
        fields = build_pow_config("UA/1")
        self.assertEqual(fields[2], 4395630592)
        self.assertEqual(fields[7:9], ["zh-CN", "en-US,en"])
        self.assertIn(fields[0], [sum(resolution) for resolution in pow_module.SCREEN_RESOLUTIONS])
        self.assertRegex(fields[1], r"GMT[+-]\d{4} \(")

    def test_proof_token_matches_web_fnv_check(self) -> None:
        # seed/difficulty 取自 2026-10-15 抓到的真实 prepare 响应
        token = build_proof_token("0.6466531835161229", "06e4f1", "UA/1", environment=self.ENVIRONMENT)
        self.assertTrue(token.startswith("gAAAAAB"))
        self.assertTrue(token.endswith(POW_ANSWER_SUFFIX))
        answer = token[len("gAAAAAB"):-len(POW_ANSWER_SUFFIX)]
        self.assertLessEqual(_fnv1a_avalanche("0.6466531835161229" + answer)[:6], "06e4f1")


class TokenBuilderTests(unittest.TestCase):
    """两种请求 token 的完整形态。"""

    def test_proof_token_prefix_and_difficulty(self) -> None:
        token = build_proof_token("seed-X", "061a80", "Mozilla/5.0 test")
        self.assertTrue(token.startswith("gAAAAAB"))
        answer = token[len("gAAAAAB"):]
        self.assertTrue(answer.endswith(POW_ANSWER_SUFFIX))
        encoded = answer[: -len(POW_ANSWER_SUFFIX)]
        self.assertLessEqual(_fnv1a_avalanche("seed-X" + encoded)[:6], "061a80")

    def test_requirements_token_matches_sdk_async_format(self) -> None:
        token = build_legacy_requirements_token("Mozilla/5.0 test")
        self.assertTrue(token.startswith("gAAAAAC"))
        answer = token[len("gAAAAAC"):]
        self.assertTrue(answer.endswith(POW_ANSWER_SUFFIX))
        encoded = answer[: -len(POW_ANSWER_SUFFIX)]
        self.assertLessEqual(_fnv1a_avalanche(POW_REQUIREMENTS_SEED + encoded)[:1], "0")

    def test_requirements_falls_back_to_blocking_format(self) -> None:
        with patch.object(pow_module, "_solve_pow_answer", return_value=None):
            token = build_legacy_requirements_token("Mozilla/5.0 test")
        self.assertTrue(token.startswith("gAAAAAC"))
        self.assertFalse(token.endswith(POW_ANSWER_SUFFIX))
        config = json.loads(pybase64.b64decode(token[len("gAAAAAC"):]))
        self.assertEqual(len(config), 25)

    def test_proof_token_raises_when_unsolvable(self) -> None:
        with patch.object(pow_module, "_solve_pow_answer", return_value=None):
            with self.assertRaises(RuntimeError):
                build_proof_token("seed", "061a80", "Mozilla/5.0 test")


if __name__ == "__main__":
    unittest.main()
