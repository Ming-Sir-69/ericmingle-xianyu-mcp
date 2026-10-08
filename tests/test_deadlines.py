"""Offline contract tests: no upstream imports, cookies, network or real messages.

Load the production wrapper definitions through AST, with the current upstream
init/send loop represented by small stubs. This tests deadlines and forwarding;
it does not claim that a remote server acknowledged an actual message.
Run: python -m unittest discover -s 闲鱼MCP/tests -v
"""
import ast
import asyncio
import json
import threading
import time
import types
import unittest
from concurrent.futures import Future
from pathlib import Path


SOURCE = Path(__file__).resolve().parents[1] / "deploy" / "xianyu_plus.py"


def contract():
    class Auth:
        def get_token(self, *, max_attempts=3):
            return self.fetch(max_attempts)

    class Client:
        def __init__(self, session):
            self.session = session

    class Live:
        async def init(self, ws):
            token = self.xianyu.get_token()
            await ws.send(json.dumps({"lwp": "/reg", "token": token, "did": self.device_id}))

        async def create_chat(self, ws, toid, item_id):
            self.create_calls += 1

        async def send_msg(self, ws, cid, toid, message):
            self.send_calls += 1
            if self.send_error:
                raise self.send_error
            if self.send_gate:
                await self.send_gate.wait()
            await ws.send(json.dumps({"lwp": "/r/MessageSend/sendByReceiverScope", "headers": {"mid": "offline-mid"}}))

        async def send_msg_once(self, toid, item_id, send_message):
            # Current upstream contract: init is synchronous internally;
            # the broad catch includes send_msg and can re-enter it.
            await self.init(self.ws)
            await self.create_chat(self.ws, toid, item_id)
            async for raw in self.ws:
                try:
                    message = json.loads(raw)
                    cid = message["body"]["singleChatConversation"]["cid"].split("@")[0]
                    await self.send_msg(self.ws, cid, toid, send_message)
                    return
                except Exception:
                    pass

    ns = {"AuthApi": Auth, "xy_client": types.SimpleNamespace(XianyuClient=Client),
          "xy_live": types.SimpleNamespace(XianyuLive=Live)}
    names = {"HTTP_CONNECT_SECONDS", "HTTP_READ_SECONDS", "TOKEN_WAIT_SECONDS", "CHAT_WAIT_SECONDS",
             "TOKEN_TTL", "_http_deadline", "_token_cache", "_token_inflight", "_token_lock",
             "_orig_get_token", "_fetch_token", "_cached_get_token", "_limit_http_session",
             "_orig_client_init", "_client_init", "_orig_live_init", "_orig_send_msg_once",
             "_ReadyTokenApi", "_LiveView", "_RegWaitWS", "_live_init", "_ChatSendFailed", "_ChatAttempt",
             "_consume_chat_task", "_send_msg_once"}
    nodes = []
    for node in ast.parse(SOURCE.read_text()).body:
        if isinstance(node, ast.Import) and all(n.name in {"asyncio", "json", "threading", "time"} for n in node.names):
            nodes.append(node)
        elif isinstance(node, ast.ImportFrom) and node.module in {"concurrent.futures", "contextvars"}:
            nodes.append(node)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name in names:
            nodes.append(node)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(t, ast.Name) and t.id in names for t in targets):
                nodes.append(node)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(SOURCE), "exec"), ns)
    Auth.get_token = ns["_cached_get_token"]
    Client.__init__ = ns["_client_init"]
    Live.init = ns["_live_init"]
    Live.send_msg_once = ns["_send_msg_once"]
    ns.update(Auth=Auth, Client=Client, Live=Live)
    ns["TOKEN_WAIT_SECONDS"] = .08
    ns["CHAT_WAIT_SECONDS"] = .12
    return ns


class FakeSession:
    def __init__(self):
        self.calls = []
        self.cookies = {"cookie2": "fake-test-session"}

    def request(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return "offline-response"


class FakeWS:
    """Models the real server: /reg must be confirmed before anything else, every message gets a reply by mid."""

    def __init__(self, repeats=0, send_code=200, ack=True):
        self.sent = []
        self.repeats = repeats
        self.send_code = send_code
        self.ack = ack
        self.replies = asyncio.Queue()

    async def send(self, text):
        msg = json.loads(text)
        self.sent.append(msg)
        if msg.get("lwp") == "/reg":
            self.replies.put_nowait({"code": 200, "headers": {"reg-uid": "offline"}})
        elif msg.get("lwp") == "/r/MessageSend/sendByReceiverScope" and self.ack:
            self.replies.put_nowait({"code": self.send_code, "headers": {"mid": msg["headers"]["mid"]}})

    async def recv(self):
        return json.dumps(await self.replies.get())

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self.repeats:
            self.repeats -= 1
            return '{"body":{"singleChatConversation":{"cid":"offline@goofish"}}}'
        await asyncio.Future()


def auth(ns, fetch):
    obj = ns["Auth"]()
    obj.client = types.SimpleNamespace(device_id="fake-device", session=FakeSession())
    obj.fetch = fetch
    return obj


def live(ns, token_api, repeats=0):
    obj = ns["Live"]()
    obj.xianyu = token_api
    obj.ws = FakeWS(repeats)
    obj.device_id = "stable-offline-device"
    obj.create_calls = obj.send_calls = 0
    obj.send_error = obj.send_gate = None
    return obj


class SyncDeadlines(unittest.TestCase):
    def test_http_defaults_explicit_and_single_install(self):
        ns = contract()
        session = FakeSession()
        client = ns["Client"](session)
        installed = client.session.request
        ns["_limit_http_session"](session)
        self.assertIs(session.request, installed)
        self.assertEqual(session.request("POST", "offline"), "offline-response")
        self.assertEqual(session.calls[-1][1]["timeout"], (5.0, 20.0))
        session.request("POST", "offline", timeout=None)
        self.assertEqual(session.calls[-1][1]["timeout"], (5.0, 20.0))
        session.request("POST", "offline", timeout=(1, 2))
        self.assertEqual(session.calls[-1][1]["timeout"], (1, 2))

    def test_http_deadline_clamps_and_stops_expired_call(self):
        ns = contract()
        session = FakeSession()
        ns["_limit_http_session"](session)
        marker = ns["_http_deadline"].set(time.monotonic() + .05)
        try:
            session.request("POST", "offline")
            timeout = session.calls[-1][1]["timeout"]
            self.assertTrue(all(0 < value <= .05 for value in timeout))
        finally:
            ns["_http_deadline"].reset(marker)
        marker = ns["_http_deadline"].set(time.monotonic() - 1)
        try:
            with self.assertRaises(TimeoutError):
                session.request("POST", "offline")
            self.assertEqual(len(session.calls), 1)
        finally:
            ns["_http_deadline"].reset(marker)

    def test_token_cache_preserves_attempts_and_original_error(self):
        ns = contract()
        calls = []
        token = {"data": {"accessToken": "offline-token"}}
        obj = auth(ns, lambda attempts: (calls.append(attempts), token)[1])
        self.assertIs(obj.get_token(max_attempts=2), token)
        self.assertIs(obj.get_token(), token)
        self.assertEqual(calls, [2])
        ns["_token_cache"].clear()
        original = ValueError("offline-guardrail-error")
        obj.fetch = lambda _: (_ for _ in ()).throw(original)
        with self.assertRaises(ValueError) as caught:
            obj.get_token()
        self.assertIs(caught.exception, original)

    def test_blocking_token_bounded_no_parallel_retry_or_late_cache(self):
        ns = contract()
        release = threading.Event()
        calls = []
        def fetch(attempts):
            calls.append(attempts)
            release.wait(2)
            return {"data": {"accessToken": "late-offline-token"}}
        obj = auth(ns, fetch)
        started = time.monotonic()
        try:
            with self.assertRaisesRegex(RuntimeError, "等待上限"):
                obj.get_token()
            self.assertLess(time.monotonic() - started, .3)
            with self.assertRaisesRegex(RuntimeError, "等待上限"):
                obj.get_token()
            self.assertEqual(calls, [3])
        finally:
            release.set()
        # Observe completion without arbitrary fixed sleeps.
        limit = time.monotonic() + .3
        while ns["_token_inflight"] and time.monotonic() < limit:
            time.sleep(.001)
        self.assertFalse(ns["_token_inflight"])
        self.assertFalse(ns["_token_cache"])

    def test_token_lock_contention_crossing_deadline_cannot_cache_result(self):
        ns = contract()
        fetched = threading.Event()
        token = {"data": {"accessToken": "offline-contended-token"}}
        obj = auth(ns, lambda _: (fetched.set(), token)[1])
        key = (obj.client.device_id, obj.client.session.cookies["cookie2"])
        future = Future()
        deadline = time.monotonic() + .04
        with ns["_token_lock"]:
            ns["_token_inflight"][key] = (future, deadline)
            worker = threading.Thread(target=ns["_fetch_token"], args=(obj, key, 3, deadline, future))
            worker.start()
            self.assertTrue(fetched.wait(.2))
            # Wait until the absolute deadline while still holding the cache lock.
            threading.Event().wait(max(0, deadline - time.monotonic()) + .02)
        worker.join(.3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(future.result(), token)
        self.assertFalse(ns["_token_cache"])
        self.assertFalse(ns["_token_inflight"])

    def test_superseded_token_flight_cannot_cache_or_remove_current_flight(self):
        ns = contract()
        obj = auth(ns, lambda _: {"data": {"accessToken": "offline-superseded-token"}})
        key = (obj.client.device_id, obj.client.session.cookies["cookie2"])
        superseded, current = Future(), Future()
        deadline = time.monotonic() + 1
        ns["_token_inflight"][key] = (current, deadline)
        ns["_fetch_token"](obj, key, 3, deadline, superseded)
        self.assertTrue(superseded.done())
        self.assertFalse(ns["_token_cache"])
        self.assertIs(ns["_token_inflight"][key][0], current)


class AsyncDeadlines(unittest.IsolatedAsyncioTestCase):
    async def test_token_wait_does_not_block_event_loop_and_init_forwards(self):
        ns = contract()
        release = threading.Event()
        obj = live(ns, auth(ns, lambda _: (release.wait(2), {"data": {"accessToken": "offline"}})[1]))
        task = asyncio.create_task(obj.init(obj.ws))
        try:
            await asyncio.sleep(.02)
            self.assertFalse(task.done())
            release.set()
            await task
            self.assertEqual(obj.ws.sent[0]["did"], "stable-offline-device")
            self.assertEqual(obj.ws.sent[0]["token"], {"data": {"accessToken": "offline"}})
        finally:
            release.set()
            if not task.done():
                task.cancel()

    async def test_missing_chat_confirmation_returns_unknown_by_deadline(self):
        ns = contract()
        obj = live(ns, auth(ns, lambda _: {"data": {"accessToken": "offline"}}))
        started = time.monotonic()
        with self.assertRaisesRegex(RuntimeError, "结果未知.*勿直接重发"):
            await obj.send_msg_once("fake-user", "fake-item", "fake-message")
        self.assertLess(time.monotonic() - started, .35)
        self.assertEqual(obj.create_calls, 1)
        self.assertEqual(obj.send_calls, 0)
        await asyncio.sleep(0)

    async def test_upstream_swallowed_send_error_cannot_repeat(self):
        ns = contract()
        obj = live(ns, auth(ns, lambda _: {"data": {"accessToken": "offline"}}), repeats=3)
        obj.send_error = ConnectionError("offline-write-might-have-completed")
        with self.assertRaisesRegex(RuntimeError, "结果未知.*勿直接重发"):
            await obj.send_msg_once("fake-user", "fake-item", "fake-message")
        self.assertEqual(obj.send_calls, 1)
        self.assertEqual(obj.ws.repeats, 2)

    async def test_blocked_write_times_out_without_second_send(self):
        ns = contract()
        obj = live(ns, auth(ns, lambda _: {"data": {"accessToken": "offline"}}), repeats=3)
        obj.send_gate = asyncio.Event()
        with self.assertRaisesRegex(RuntimeError, "结果未知"):
            await obj.send_msg_once("fake-user", "fake-item", "fake-message")
        obj.send_gate.set()
        await asyncio.sleep(0)
        self.assertEqual(obj.send_calls, 1)
        self.assertEqual(obj.ws.repeats, 2)

    async def test_success_forwards_once_and_returns_upstream_result(self):
        ns = contract()
        obj = live(ns, auth(ns, lambda _: {"data": {"accessToken": "offline"}}), repeats=2)
        self.assertIsNone(await obj.send_msg_once("fake-user", "fake-item", "fake-message"))
        self.assertEqual(obj.send_calls, 1)

    async def test_rejected_send_reply_is_reported_not_success(self):
        ns = contract()
        obj = live(ns, auth(ns, lambda _: {"data": {"accessToken": "offline"}}), repeats=2)
        obj.ws.send_code = 400
        with self.assertRaisesRegex(RuntimeError, "拒绝"):
            await obj.send_msg_once("fake-user", "fake-item", "fake-message")
        self.assertEqual(obj.send_calls, 1)

    async def test_missing_send_reply_is_unknown_not_success(self):
        ns = contract()
        obj = live(ns, auth(ns, lambda _: {"data": {"accessToken": "offline"}}), repeats=2)
        obj.ws.ack = False
        with self.assertRaisesRegex(RuntimeError, "结果未知"):
            await obj.send_msg_once("fake-user", "fake-item", "fake-message")
        self.assertEqual(obj.send_calls, 1)

    async def test_create_waits_for_reg_confirmation(self):
        ns = contract()
        obj = live(ns, auth(ns, lambda _: {"data": {"accessToken": "offline"}}), repeats=2)
        order = []
        original_create = obj.create_chat
        async def create(ws, toid, item_id):
            order.append(("create", obj.ws.replies.qsize()))
            return await original_create(ws, toid, item_id)
        obj.create_chat = create
        await obj.send_msg_once("fake-user", "fake-item", "fake-message")
        self.assertEqual(order, [("create", 0)])  # reg reply already consumed before create

    async def test_send_risk_error_keeps_guardrail_marker_and_cause(self):
        ns = contract()
        obj = live(ns, auth(ns, lambda _: {"data": {"accessToken": "offline"}}), repeats=2)
        original = RuntimeError("FAIL_SYS_USER_VALIDATE offline-risk")
        obj.send_error = original
        with self.assertRaisesRegex(RuntimeError, "FAIL_SYS_USER_VALIDATE") as caught:
            await obj.send_msg_once("fake-user", "fake-item", "fake-message")
        self.assertIs(caught.exception.__cause__.__cause__, original)
        self.assertEqual(obj.send_calls, 1)

    async def test_cancel_resistant_cleanup_does_not_extend_deadline_or_send_late(self):
        ns = contract()
        obj = live(ns, auth(ns, lambda _: {"data": {"accessToken": "offline"}}))
        finished = asyncio.Event()
        async def slow_original(view, *args, **kwargs):
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                await asyncio.sleep(.05)  # Simulate asynchronous WebSocket close.
            try:
                await view.send_msg(obj.ws, "fake-cid", "fake-user", "fake-message")
            finally:
                finished.set()
        ns["_orig_send_msg_once"] = slow_original
        started = time.monotonic()
        with self.assertRaisesRegex(RuntimeError, "结果未知"):
            await obj.send_msg_once("fake-user", "fake-item", "fake-message")
        self.assertLess(time.monotonic() - started, .16)
        await asyncio.wait_for(finished.wait(), .3)
        self.assertEqual(obj.send_calls, 0)


if __name__ == "__main__":
    unittest.main()
