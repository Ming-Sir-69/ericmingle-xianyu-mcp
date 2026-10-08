"""Optional offline integration against installed upstream dependencies.

Uses only an isolated temporary repo and synthetic session data; all HTTP and
WebSocket transports are replaced before invocation. Missing dependencies skip
these checks, while test_deadlines.py remains runnable with the standard library.
"""
import asyncio
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


HAS_RUNTIME = bool(importlib.util.find_spec("pyxianyu") and importlib.util.find_spec("xianyu_mcp"))
SOURCE = Path(__file__).resolve().parents[1] / "deploy" / "xianyu_plus.py"


@unittest.skipUnless(HAS_RUNTIME, "pyxianyu/xianyu_mcp not installed; contract stubs run separately")
class RuntimeContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="xianyu-offline-contract-")
        cls.fake_cookie = Path(cls.temp.name) / "fake_cookie.txt"
        cls.fake_cookie.write_text("unb=offline; _m_h5_tk=offline_token; cookie2=offline-cookie")
        cls.env = patch.dict(os.environ, {"XIANYU_REPO_ROOT": cls.temp.name,
                                         "XIANYU_COOKIE_FILE": str(cls.fake_cookie),
                                         "XIANYU_COOKIE": "", "XIANYU_SETUP_AUTOSTART": "0",
                                         "XIANYU_LOG_TO_FILE": "0", "XIANYU_EGRESS_PROXY": ""})
        cls.env.start()
        spec = importlib.util.spec_from_file_location("xianyu_offline_contract", SOURCE)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    @classmethod
    def tearDownClass(cls):
        cls.env.stop()
        cls.temp.cleanup()

    def test_real_post_preserves_signing_and_sets_transport_timeout(self):
        import requests
        mod = self.module
        client = mod.xy_client.XianyuClient({"_m_h5_tk": "offline_token"}, "offline-device")
        response = requests.Response()
        response.status_code, response._content, response.url = 200, b"{}", "https://offline.invalid"
        params = {"api": "offline.test", "t": "0"}
        with patch.object(requests.Session, "send", return_value=response) as transport:
            self.assertIs(client.post_json("https://offline.invalid", params, "{}"), response)
        self.assertEqual(transport.call_count, 1)
        self.assertEqual(transport.call_args.kwargs["timeout"], (5.0, 20.0))
        self.assertTrue(params["sign"])
        self.assertEqual(transport.call_args.args[0].headers["sec-ch-ua-platform"], '"macOS"')

    def test_real_init_and_send_forward_protocol_once(self):
        mod = self.module
        class WS:
            def __init__(self):
                self.sent = []
                self.replies = 2
            async def send(self, raw):
                self.sent.append(json.loads(raw))
            def __aiter__(self):
                return self
            async def __anext__(self):
                if not self.replies:
                    await asyncio.Future()
                self.replies -= 1
                return '{"body":{"singleChatConversation":{"cid":"offline@goofish"}}}'
        class Connection:
            async def __aenter__(self):
                return mod._WS(ws)
            async def __aexit__(self, *exc):
                return False
        ws = WS()
        obj = mod.xy_live.XianyuLive(self.fake_cookie.read_text())
        token = {"data": {"accessToken": "offline-token"}}
        mod._token_cache.clear()
        with patch.object(mod, "_orig_get_token", return_value=token) as fetch, \
                patch.object(mod.xy_live, "_ws_connect", return_value=Connection()):
            asyncio.run(obj.send_msg_once("fake-user", "fake-item", {"type": "text", "text": "offline"}))
        self.assertEqual(fetch.call_count, 1)
        self.assertEqual([m["lwp"] for m in ws.sent],
                         ["/reg", "/r/SyncStatus/ackDiff", "/r/SingleChatConversation/create",
                          "/r/MessageSend/sendByReceiverScope"])
        self.assertEqual(ws.sent[0]["headers"]["did"], obj.device_id)
        self.assertIn("OS(Mac OS X/10.15.7)", ws.sent[0]["headers"]["ua"])
        self.assertEqual(ws.replies, 1)

    def test_tools_and_safety_hooks_remain_registered(self):
        mod = self.module
        tools = mod.mcp._tool_manager._tools
        self.assertTrue({"send_text_message", "send_image_message", "search_items", "favor_item",
                         "login_xianyu"}.issubset(tools))
        self.assertIs(mod.gr.RequestGuardrails._require_not_in_cooldown, mod._require_not_in_cooldown)
        self.assertIs(mod.gr.RequestGuardrails._on_error, mod._on_error)
        self.assertIs(mod.xy_live.generate_device_id, mod._stable_device_id)


if __name__ == "__main__":
    unittest.main()
