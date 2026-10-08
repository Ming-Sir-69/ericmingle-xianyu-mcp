"""EricMingle Xianyu extensions. GPL-3.0-only; see LICENSE and NOTICE.md.
Optional browser integration is configured by environment; no deployment is bundled.
"""

import asyncio
import dataclasses
import fcntl
import json
import os
import threading
import time
import uuid
from concurrent.futures import Future, TimeoutError as FutureTimeoutError
from contextvars import ContextVar
from datetime import datetime
from pathlib import Path

from mcp.types import BlobResourceContents, EmbeddedResource, ToolAnnotations

import pyxianyu.utils.xianyu_utils as xy_utils
import pyxianyu.xianyu_live as xy_live
from pyxianyu.apis.auth_api import AuthApi
from xianyu_mcp import guardrails as gr
from xianyu_mcp import server as up

mcp = up.mcp
mcp.settings.host = os.environ.get("MCP_HOST", "127.0.0.1")
mcp.settings.port = int(os.environ.get("MCP_PORT", "8000"))
H5 = "https://h5api.m.goofish.com/h5/{api}/1.0/"
FAVOR_TYPES = {"all": "DEFAULT", "reduced": "REDUCE", "valid": "VALID", "invalid": "INVALID"}

COOKIE_FILE = Path(os.environ.get("XIANYU_COOKIE_FILE", "data/cookie.txt"))
DEVICE_FILE = COOKIE_FILE.with_name("xianyu_device.json")   # 两个容器共用 ./data
RISK_FILE = COOKIE_FILE.with_name("xianyu_risk.json")
TOKEN_TTL = 1800            # 聊天令牌官方有效期 24 小时，这里半小时复用一次，不再每条消息都重新申请
HTTP_CONNECT_SECONDS = 5.0
HTTP_READ_SECONDS = 20.0
TOKEN_WAIT_SECONDS = 30.0   # 包含上游令牌过期重试；超时只结束等待，不重发消息
CHAT_WAIT_SECONDS = 45.0    # 建连、令牌、建会话确认、发送及关连接的总等待
_http_deadline = ContextVar("xianyu_http_deadline", default=None)
FRESH_LOGIN_SECONDS = 6 * 3600
FRESH_WRITE_INTERVAL = (60.0, 60.0)   # 新登录 6 小时内：写操作间隔 60~120 秒（平时上游默认 20~40 秒）


def _locked_json(path: Path, update):
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.touch(mode=0o600)
        os.chmod(path, 0o600)
    with path.open("r+", encoding="utf-8") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        raw = f.read()
        data = json.loads(raw) if raw.strip() else {}
        result, changed = update(data)
        if changed:
            f.seek(0); f.truncate(); f.write(json.dumps(data, ensure_ascii=False))
        return result


def _stable_device_id(user_id):
    """上游每次启动都随机生成设备 ID，重启几次在闲鱼看来就是多台新设备；这里按账号固定下来。"""
    def update(data):
        if user_id not in data:
            data[user_id] = f"{uuid.uuid4()}-{user_id}"
            return data[user_id], True
        return data[user_id], False
    return _locked_json(DEVICE_FILE, update)


xy_utils.generate_device_id = _stable_device_id
xy_live.generate_device_id = _stable_device_id

_token_cache: dict = {}
_token_inflight: dict = {}
_token_lock = threading.Lock()
_orig_get_token = AuthApi.get_token


def _fetch_token(auth, key, max_attempts, deadline, future):
    """同步 HTTP 不放在事件循环里；同一个令牌最多保留一个后台请求。"""
    marker = _http_deadline.set(deadline)
    try:
        result = _orig_get_token(auth, max_attempts=max_attempts)
        with _token_lock:
            pending = _token_inflight.get(key)
            if time.monotonic() < deadline and pending is not None and pending[0] is future:
                _token_cache[key] = (time.time(), result)
        future.set_result(result)
    except BaseException as exc:
        future.set_exception(exc)
    finally:
        _http_deadline.reset(marker)
        with _token_lock:
            if _token_inflight.get(key, (None,))[0] is future:
                _token_inflight.pop(key, None)


def _cached_get_token(self, *, max_attempts=3):
    key = (self.client.device_id, self.client.session.cookies.get("cookie2", ""))
    with _token_lock:
        hit = _token_cache.get(key)
        if hit and time.time() - hit[0] < TOKEN_TTL:
            return hit[1]
        pending = _token_inflight.get(key)
        if pending is None:
            pending = (Future(), time.monotonic() + TOKEN_WAIT_SECONDS)
            _token_inflight[key] = pending
            threading.Thread(target=_fetch_token, args=(self, key, max_attempts, pending[1], pending[0]),
                             daemon=True).start()
    future, deadline = pending
    remaining = deadline - time.monotonic()
    try:
        if remaining <= 0:
            raise FutureTimeoutError()
        result = future.result(timeout=remaining)
        if time.monotonic() >= deadline:
            raise FutureTimeoutError()
        return result
    except FutureTimeoutError as exc:
        if future.done() and future.exception() is not None:
            raise   # 上游自己的异常保留给安全校验和冷却判断
        raise RuntimeError("获取闲鱼聊天令牌超过等待上限，结果未知。请稍后核对登录状态，勿连续重试。") from exc


AuthApi.get_token = _cached_get_token

_orig_on_error = gr.RequestGuardrails._on_error
_orig_require = gr.RequestGuardrails._require_not_in_cooldown
_orig_from_env = gr.RequestGuardrailsConfig.from_env.__func__


COOLDOWNS = (1800, 7200, 21600)   # 24 小时内第 1 / 2 / 3 次起触发验证：30 分钟 / 2 小时 / 6 小时
VERIFY_HINTS = ("punish", "x5secdata", "_____tmd_____", "captcha", "verify")


def _find_verify_url(obj):
    if isinstance(obj, str):
        return obj if obj.startswith("http") and any(h in obj for h in VERIFY_HINTS) else ""
    items = obj.values() if isinstance(obj, dict) else obj if isinstance(obj, (list, tuple)) else ()
    for v in items:
        if url := _find_verify_url(v):
            return url
    return ""


def _verify_url(error):
    e, seen = error, set()
    while e is not None and id(e) not in seen:
        seen.add(id(e))
        if url := _find_verify_url(getattr(e, "payload", None) or {}):
            return url
        e = e.__cause__ or e.__context__
    return ""


def _on_error(self, error, cfg):
    _orig_on_error(self, error, cfg)
    if not self._is_strong_risk_error(error):
        return
    now = time.time()
    url = _verify_url(error)

    def update(data):
        history = [t for t in data.get("history", []) if now - t < 86400] + [now]
        until = now + COOLDOWNS[min(len(history), len(COOLDOWNS)) - 1]
        data.update(until=max(until, data.get("until", 0)), at=now, error=str(error)[:200],
                    url=url, count_24h=len(history), history=history)
        return None, True
    _locked_json(RISK_FILE, update)


def _require_not_in_cooldown(self, now):
    risk = _locked_json(RISK_FILE, lambda d: (dict(d), False))
    until = risk.get("until", 0)
    if time.time() < until:
        left = int((until - time.time()) / 60) + 1
        how = ("验证页已在 Mac 上的 Brave 里打开，拖一下滑块即可提前恢复；" if risk.get("url")
               else "可以在 Mac 上的 Brave 里打开闲鱼看看是否需要验证；")
        raise RuntimeError(
            f"闲鱼要求安全验证，发消息、收藏等写操作暂停到 {datetime.fromtimestamp(until):%H:%M}（约 {left} 分钟后自动恢复）。"
            f"{how}也可以说“登录闲鱼”重新扫码。搜索和查看不受影响，不要反复重试。")
    _orig_require(self, now)


def _from_env(cls):
    cfg = _orig_from_env(cls)
    try:
        fresh = time.time() - COOKIE_FILE.stat().st_mtime < FRESH_LOGIN_SECONDS
    except OSError:
        fresh = False
    if not fresh:
        return cfg
    return dataclasses.replace(cfg, write_min_interval=max(cfg.write_min_interval, FRESH_WRITE_INTERVAL[0]),
                               write_jitter=max(cfg.write_jitter, FRESH_WRITE_INTERVAL[1]))


gr.RequestGuardrails._on_error = _on_error
gr.RequestGuardrails._require_not_in_cooldown = _require_not_in_cooldown
gr.RequestGuardrailsConfig.from_env = classmethod(_from_env)

from pyxianyu.core import client as xy_client  # noqa: E402

BROWSER_ENV = COOKIE_FILE.with_name("browser_env.json")   # 由 NAS 上的 xianyu-env-sync 从 Mac 同步
LANG = "zh-CN,zh;q=0.9"
_fp_cache = {"mtime": None, "major": "154"}


def _chrome_major() -> str:
    """浏览器更新后内核版本会变，从同步过来的环境里读，指纹自动跟上。"""
    try:
        mtime = BROWSER_ENV.stat().st_mtime
        if mtime != _fp_cache["mtime"]:
            major = json.loads(BROWSER_ENV.read_text()).get("fingerprint", {}).get("chrome_major")
            _fp_cache.update(mtime=mtime, major=str(major or _fp_cache["major"]))
    except (OSError, ValueError):
        pass
    return _fp_cache["major"]


def _ua() -> str:
    return ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            f"(KHTML, like Gecko) Chrome/{_chrome_major()}.0.0.0 Safari/537.36")


def _im_ua() -> str:
    v = _chrome_major()
    return f"{_ua()} DingTalk(2.1.5) OS(Mac OS X/10.15.7) Browser(Chrome/{v}.0.0.0) DingWeb/2.1.5 IMPaaS DingWeb/2.1.5"


xy_client.DEFAULT_USER_AGENT = _ua()
_orig_headers = xy_client.XianyuClient.build_json_headers


def _headers(self, include_host=False):
    v = _chrome_major()
    h = _orig_headers(self, include_host=include_host)
    h.update({"user-agent": _ua(), "sec-ch-ua": f'"Chromium";v="{v}", "Brave";v="{v}", "Not A(Brand";v="99"',
              "sec-ch-ua-platform": '"macOS"', "accept-language": LANG})
    return h


xy_client.XianyuClient.build_json_headers = _headers


def _limit_http_session(session):
    """覆盖这个闲鱼 Session，保留上游签名、错误类型及重试规则。"""
    if getattr(session, "_xianyu_timeout_installed", False):
        return
    request = session.request

    def bounded_request(*args, **kwargs):
        timeout = kwargs.get("timeout")
        if timeout is None:
            timeout = (HTTP_CONNECT_SECONDS, HTTP_READ_SECONDS)
        deadline = _http_deadline.get()
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("闲鱼令牌请求已超过总等待上限")
            parts = timeout if isinstance(timeout, tuple) else (timeout, timeout)
            timeout = tuple(min(part or remaining, remaining) for part in parts)
        kwargs["timeout"] = timeout
        return request(*args, **kwargs)

    session.request = bounded_request
    session._xianyu_timeout_installed = True


_orig_client_init = xy_client.XianyuClient.__init__


def _client_init(self, *args, **kwargs):
    _orig_client_init(self, *args, **kwargs)
    _limit_http_session(self.session)


xy_client.XianyuClient.__init__ = _client_init


class _WS:
    """聊天长连接：握手头和登记消息里的 UA 换成同一套。"""
    def __init__(self, ws):
        self._ws = ws

    def __getattr__(self, name):
        return getattr(self._ws, name)

    def __aiter__(self):
        return self._ws.__aiter__()

    async def send(self, message):
        if isinstance(message, str) and '"/reg"' in message:
            obj = json.loads(message)
            obj.get("headers", {})["ua"] = _im_ua()
            message = json.dumps(obj)
        return await self._ws.send(message)


class _WSConnect:
    def __init__(self, cm):
        self._cm = cm

    async def __aenter__(self):
        return _WS(await self._cm.__aenter__())

    async def __aexit__(self, *exc):
        return await self._cm.__aexit__(*exc)




def _ws_connect(url, headers):
    headers = {**headers, "User-Agent": _ua(), "Accept-Language": LANG}
    import websockets
    return _WSConnect(websockets.connect(url, additional_headers=headers, proxy=_egress() or None,
                                        open_timeout=HTTP_CONNECT_SECONDS, close_timeout=2))


xy_live._ws_connect = _ws_connect

_orig_live_init = xy_live.XianyuLive.init
_orig_send_msg_once = xy_live.XianyuLive.send_msg_once


class _ReadyTokenApi:
    def __init__(self, api, token):
        self._api, self._token = api, token

    def __getattr__(self, name):
        return getattr(self._api, name)

    def get_token(self):
        return self._token


class _LiveView:
    def __init__(self, live):
        self._live = live

    def __getattr__(self, name):
        return getattr(self._live, name)


class _RegWaitWS:
    """上游 init 发完 /reg 立刻发 ackDiff，随后马上建会话；服务端在注册确认前收到的请求一律回 400，
    建会话拿不到 cid，发送就一直等到超时。这里在 /reg 发出后等到注册确认（200 + reg-uid）再继续。"""

    def __init__(self, ws):
        self._ws = ws

    def __getattr__(self, name):
        return getattr(self._ws, name)

    async def send(self, message):
        await self._ws.send(message)
        if '"/reg"' not in message:
            return
        async def wait_reg():
            while True:
                reply = json.loads(await self._ws.recv())
                if reply.get("code") == 200 and "reg-uid" in (reply.get("headers") or {}):
                    return
                if isinstance(reply.get("code"), int) and reply["code"] >= 400 and "reg" in str(reply.get("headers")):
                    raise RuntimeError(f"闲鱼聊天注册被拒绝：{reply.get('code')}")
        await asyncio.wait_for(wait_reg(), timeout=10)


async def _live_init(self, ws):
    token = await asyncio.to_thread(self.xianyu.get_token)
    view = _LiveView(self)
    view.xianyu = _ReadyTokenApi(self.xianyu, token)
    return await _orig_live_init(view, _RegWaitWS(ws))


class _ChatSendFailed(BaseException):
    """绕过当前上游的 except Exception，确保一次调用最多发送一次。"""


class _ChatAttempt(_LiveView):
    attempted = False
    expired = False

    async def send_msg(self, *args, **kwargs):
        if self.expired or self.attempted:
            raise _ChatSendFailed("聊天等待已结束，不再发送")
        self.attempted = True
        ws, rest = args[0], args[1:]
        sent = []

        class _Capture:
            def __getattr__(_, name):
                return getattr(ws, name)

            async def send(_, message):
                sent.append(json.loads(message))
                await ws.send(message)

        try:
            result = await self._live.send_msg(_Capture(), *rest, **kwargs)
            if not sent:
                raise RuntimeError("消息未写出")
            # 上游写完就返回并关连接，服务端尚未落库时消息会丢；等到同 mid 的 200 回执才算发送成功。
            mid = sent[-1]["headers"]["mid"]
            while True:
                reply = json.loads(await ws.recv())
                if (reply.get("headers") or {}).get("mid") == mid:
                    if reply.get("code") != 200:
                        raise RuntimeError(f"闲鱼拒绝了这条消息：{reply.get('code')}")
                    return result
        except Exception as exc:
            raise _ChatSendFailed(str(exc)) from exc


def _consume_chat_task(task):
    if not task.cancelled():
        task.exception()


async def _send_msg_once(self, *args, **kwargs):
    attempt = _ChatAttempt(self)
    task = asyncio.create_task(_orig_send_msg_once(attempt, *args, **kwargs))
    try:
        done, _ = await asyncio.wait({task}, timeout=CHAT_WAIT_SECONDS)
        if not done:
            attempt.expired = True
            task.cancel()
            task.add_done_callback(_consume_chat_task)
            raise RuntimeError("闲鱼聊天超过总等待上限，结果未知。请先查看聊天记录确认，勿直接重发。")
        return task.result()
    except _ChatSendFailed as exc:
        raise RuntimeError(f"{exc}\n闲鱼消息发送未完成，结果未知。请先查看聊天记录确认，勿直接重发。") from exc
    except BaseException:
        if not task.done():
            attempt.expired = True
            task.cancel()
            task.add_done_callback(_consume_chat_task)
        raise


xy_live.XianyuLive.init = _live_init
xy_live.XianyuLive.send_msg_once = _send_msg_once

EGRESS = os.environ.get("XIANYU_EGRESS_PROXY", "")   # 例如 http://xianyu-egress:7897
_egress_state = {"at": 0.0, "ok": False}


def _egress() -> str:
    if not EGRESS:
        return ""
    now = time.time()
    if now - _egress_state["at"] > 20:
        import socket
        from urllib.parse import urlparse
        u = urlparse(EGRESS)
        try:
            socket.create_connection((u.hostname, u.port), timeout=1.5).close()
            _egress_state["ok"] = True
        except OSError:
            _egress_state["ok"] = False
        _egress_state["at"] = now
    return EGRESS if _egress_state["ok"] else ""

_orig_post = xy_client.XianyuClient.post_json
_cookie_lock = threading.Lock()


def _post_json(self, url, params, data_val, headers=None, verify=None):
    _limit_http_session(self.session)
    proxy = _egress()
    self.session.proxies = {"http": proxy, "https": proxy} if proxy else {}
    response = _orig_post(self, url, params, data_val, headers=headers, verify=verify)
    try:
        _persist_cookies({c.name: c.value for c in self.session.cookies if c.value})
    except Exception:
        pass
    return response


def _persist_cookies(fresh: dict):
    with _cookie_lock:
        raw = COOKIE_FILE.read_text(encoding="utf-8").strip()
        pairs = dict(p.strip().split("=", 1) for p in raw.split(";") if "=" in p)
        if fresh.get("unb") and pairs.get("unb") and fresh["unb"] != pairs["unb"]:
            return   # 换了账号的旧进程，不回写
        merged = {**pairs, **{k: v for k, v in fresh.items() if k in pairs or k.startswith(("_m_h5_tk", "x5"))}}
        if merged == pairs:
            return
        tmp = COOKIE_FILE.with_name(COOKIE_FILE.name + ".tmp")
        tmp.write_text("; ".join(f"{k}={v}" for k, v in merged.items()), encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.utime(tmp, (COOKIE_FILE.stat().st_atime, COOKIE_FILE.stat().st_mtime))  # 保留"登录时间"，不重置新登录缓冲
        tmp.replace(COOKIE_FILE)


xy_client.XianyuClient.post_json = _post_json


def _mtop(api: str, data: dict, write: bool) -> dict:
    tools = up._get_tools()
    client = tools._get_item_api().client
    params = client.build_mtop_params(api=api, spm_cnt="a21ybx.collection.0.0",
                                      spm_pre="a21ybx.item.0.0", log_id="xianyu_plus")

    def call():
        response = client.post_json(H5.format(api=api), params=params,
                                    data_val=json.dumps(data, ensure_ascii=False, separators=(",", ":")))
        result = client.parse_json_response(response, api_name=api)
        return client.ensure_api_success(result, api_name=api)

    return tools._guardrails.run_write(call) if write else tools._guardrails.run_read(call)


@mcp.tool()
def favor_item(item_id: str) -> str:
    """把闲鱼商品加入“我的收藏”（和 App 里点收藏一样，手机上同步可见，降价会提醒）。

    Args:
        item_id: 商品 ID，例如 914138117361。
    """
    if payload := up._maybe_requires_login_payload():
        return up.dump_json(payload)
    result = _mtop("mtop.taobao.idle.collect.item", {"itemId": str(item_id).strip()}, write=True)
    return up.dump_json({"success": True, "item_id": str(item_id).strip(), "raw": result})


@mcp.tool()
def unfavor_item(item_id: str) -> str:
    """把商品从“我的收藏”里移除。

    Args:
        item_id: 商品 ID。
    """
    if payload := up._maybe_requires_login_payload():
        return up.dump_json(payload)
    result = _mtop("com.taobao.idle.unfavor.item", {"itemId": str(item_id).strip()}, write=True)
    return up.dump_json({"success": True, "item_id": str(item_id).strip(), "raw": result})


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def list_favorites(filter: str = "all", page_number: int = 1) -> str:
    """列出“我的收藏”，每页 20 条。

    Args:
        filter: all=全部，reduced=降价宝贝，valid=有效宝贝，invalid=失效宝贝（已卖出/下架）。
        page_number: 页码，从 1 开始；has_next_page 为 true 表示还有下一页。
    """
    if payload := up._maybe_requires_login_payload():
        return up.dump_json(payload)
    kind = FAVOR_TYPES.get(filter.strip().lower())
    if not kind:
        raise ValueError("filter 只能是 all / reduced / valid / invalid")
    result = _mtop("mtop.taobao.idle.web.favor.item.list",
                   {"pageNumber": int(page_number), "rowsPerPage": 20, "type": kind}, write=False)
    data = result.get("data", {}) or {}
    items = [{
        "item_id": str(it.get("id")),
        "title": it.get("title"),
        "price": it.get("price"),
        "original_price": it.get("originalPrice"),
        "location": f"{it.get('province') or ''}{it.get('city') or ''}",
        "seller": it.get("userNick"),
        "want_count": it.get("wantUv"),
        "favored_at": it.get("favorTime"),
        "invalid": bool(it.get("itemDeleted") or it.get("offline") or it.get("itemStatus")),
        "image": it.get("picUrl"),
        "url": f"https://www.goofish.com/item?id={it.get('id')}",
    } for it in data.get("items") or []]
    return up.dump_json({"filter": filter, "page_number": int(page_number),
                         "has_next_page": bool(data.get("nextPage")), "items": items})


MAC_HOST = os.environ.get("XIANYU_BROWSER_HOST", "")
MAC_USER = os.environ.get("XIANYU_BROWSER_USER", "")
MAC_KEY = os.environ.get("XIANYU_BROWSER_KEY_FILE", "")
MAC_KNOWN = os.environ.get("XIANYU_BROWSER_KNOWN_HOSTS", "")   # Mac 上被限定只能执行固定指令
LOGIN_HINT = "闲鱼登录已失效或未登录：请调用 login_xianyu 获取登录二维码，用手机闲鱼 App 扫码。"
NAS_LOGIN_MARK = COOKIE_FILE.with_name("nas_login.json")   # 最近一次 NAS 扫码登录的记录（给同步规则和排查用）
QR_WATCH_SECONDS = 180

for name in ("qr_login_generate", "qr_login_status", "qr_login_cookie", "qr_login_save_env"):
    mcp._tool_manager._tools.pop(name, None)


def _no_cookie_payload():
    """上游在没有 Cookie 时会在 NAS 上自动生成扫码会话；改为直接提示调用 login_xianyu。"""
    if up._load_cookie_str():
        return None
    return {"success": False, "requires_login": True, "message": LOGIN_HINT}


up._maybe_requires_login_payload = _no_cookie_payload


def _mac(command: str, timeout: float = 90) -> dict:
    if not all((MAC_HOST, MAC_USER, MAC_KEY, MAC_KNOWN)):
        raise RuntimeError("Optional browser SSH integration is not configured")
    import paramiko
    client = paramiko.SSHClient()
    client.load_host_keys(MAC_KNOWN)
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(MAC_HOST, username=MAC_USER, key_filename=MAC_KEY, timeout=15,
                       allow_agent=False, look_for_keys=False)
        _, stdout, _ = client.exec_command(command, timeout=timeout)
        return json.loads(stdout.read().decode() or "{}")
    finally:
        client.close()


def _nas_login_valid() -> bool:
    """结果判断：NAS 当前的登录能不能用（和自检 xianyu_login 同一个标准）。"""
    try:
        return bool(up._load_cookie_str()) and "登录态有效" in str(up._get_tools().validate_login())
    except Exception:
        return False


def _save_nas_login(cookie_str: str, unb: str) -> None:
    pairs = dict(p.strip().split("=", 1) for p in cookie_str.split(";") if "=" in p)
    with _cookie_lock:
        tmp = COOKIE_FILE.with_name(COOKIE_FILE.name + ".tmp")
        tmp.write_text("; ".join(f"{k}={v}" for k, v in pairs.items()), encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(COOKIE_FILE)   # 不保留旧时间：这是一次新登录
    NAS_LOGIN_MARK.write_text(json.dumps({"unb": unb or pairs.get("unb", ""), "cookie2": pairs.get("cookie2", ""),
                                          "at": time.strftime("%Y-%m-%d %H:%M:%S")}, ensure_ascii=False))
    os.chmod(NAS_LOGIN_MARK, 0o600)


def _watch_nas_qr(session_id: str) -> None:
    """后台等扫码：成功（且拿到接口令牌）就写入 NAS 登录；超时或失败只记日志，结果由自检按有效性判断。"""
    mgr = up._get_qr_login()
    deadline = time.time() + QR_WATCH_SECONDS + 60
    while time.time() < deadline:
        time.sleep(2)
        st = mgr.get_status(session_id)
        status = st.get("status")
        if status == "success" and st.get("has_mtop_token"):
            ck = mgr.get_cookie(session_id)
            if ck.get("success") and "_m_h5_tk=" in (ck.get("cookie") or ""):
                _save_nas_login(ck["cookie"], ck.get("unb", ""))
                up.logger.info("NAS 扫码登录成功，已写入登录凭证")
                return
        if status in {"expired", "error", "canceled"}:
            up.logger.info("NAS 扫码未完成：{}", status)
            return
    up.logger.info("NAS 扫码等待超时")


async def _nas_qr() -> list:
    r = await up._get_qr_login().generate()
    url = r.get("qr_data_url") or ""
    if not r.get("success") or "," not in url:
        return [up.dump_json({"success": False, "message": f"NAS 生成二维码失败：{r.get('message') or r.get('status')}"})]
    threading.Thread(target=_watch_nas_qr, args=(r["session_id"],), daemon=True).start()
    return [
        up.dump_json({"success": True, "status": "waiting_scan", "where": "nas",
                      "message": "这是 NAS 直接生成的登录二维码：用手机闲鱼 App「扫一扫」扫码并确认，约 3 分钟有效；"
                                 "成功后立即生效，不经过 浏览器宿主。"}),
        EmbeddedResource(type="resource", resource=BlobResourceContents(
            uri="file:///xianyu-login-qr.png", mimeType=url[5:url.index(";")] if url.startswith("data:") else "image/png",
            blob=url.split(",", 1)[1])),
    ]


def _mac_qr(force: bool) -> list | None:
    """浏览器宿主 的 Brave 出码；连不上 Mac 或出码失败时返回 None，由调用方改走 NAS。"""
    try:
        r = _mac("login-qr-force" if force else "login-qr")
    except Exception:
        return None
    status = r.get("status")
    if status == "already_logged_in":
        return [up.dump_json({"success": True, "status": "already_logged_in", "where": "mac",
                              "message": "浏览器宿主 的 Brave 里闲鱼已登录（已核实收藏页），登录已导出，请核对自行配置的凭据同步。"})]
    if status != "qr" or not r.get("png_base64"):
        return None
    return [
        up.dump_json({"success": True, "status": "waiting_scan", "where": "mac",
                      "message": "请用手机闲鱼 App「扫一扫」扫描二维码并确认登录；二维码约 3 分钟有效，"
                                 "扫码成功后约 2~4 分钟生效。在手机上查看时，可保存图片后在闲鱼扫一扫里从相册识别。"}),
        EmbeddedResource(type="resource", resource=BlobResourceContents(
            uri="file:///xianyu-login-qr.png", mimeType="image/png", blob=r["png_base64"])),
    ]


@mcp.tool()
async def login_xianyu(force_relogin: bool = False, via: str = "auto") -> list:
    """登录闲鱼：只看结果。当前登录有效就直接返回，不打扰；否则返回登录二维码图片文件，
    请把这个文件发送给用户，让用户用手机闲鱼 App「扫一扫」扫码并确认。用户用任何方式登录都算数
    （扫这个二维码，或直接在 浏览器宿主 的 Brave 里登录闲鱼），同步与通知需另行配置。

    Args:
        force_relogin: 默认 false。true 时即使当前登录有效也重新出码。
        via: auto（默认，优先 浏览器宿主 的 Brave 出码，Mac 不可用时自动改由 NAS 出码）/ mac / nas。
            用户说不想经过 浏览器宿主、或 Mac 关机时用 nas：NAS 直接出码，扫码成功立即生效。
    """
    via = (via or "auto").strip().lower()
    if not force_relogin and _nas_login_valid():
        return [up.dump_json({"success": True, "status": "already_valid",
                              "message": "闲鱼登录当前有效，无需重新登录。"})]
    if via in {"auto", "mac"}:
        result = _mac_qr(force_relogin)
        if result is not None:
            return result
        if via == "mac":
            return [up.dump_json({"success": False, "message": "连不上 浏览器宿主 上的浏览器，可改用 via=nas 由 NAS 直接出码。"})]
    return await _nas_qr()


LOGIN_ERRORS = ("令牌过期", "TOKEN_EXOIRED", "TOKEN_EXPIRED", "SESSION_EXPIRED", "FAIL_SYS_SESSION",
                "requires_login", "未登录", "登录态", "_m_h5_tk")


def _with_login_hint(tool):
    """登录失效时，在报错后面补一句怎么恢复（用到时才提示，不主动提醒）。"""
    fn = tool.fn

    def hinted(exc):
        msg = str(exc)
        return RuntimeError(f"{msg}\n{LOGIN_HINT}") if any(k in msg for k in LOGIN_ERRORS) else exc

    if tool.is_async:
        async def wrapper(*args, **kwargs):
            try:
                return await fn(*args, **kwargs)
            except Exception as e:
                raise hinted(e) from e
    else:
        def wrapper(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except Exception as e:
                raise hinted(e) from e
    tool.fn = wrapper


from xianyu_mcp.tools import xianyu_api_tools as _xat  # noqa: E402

_orig_get_my_profile = _xat.XianYuApiTools.get_my_profile
_NAV_COUNTS = {"followers": "followers", "following": "following", "soldCount": "sold_count",
               "purchaseCount": "purchase_count", "collectionCount": "collection_count"}


def _profile_from_nav(self):
    """闲鱼导航接口现在把资料放在 data.module.base（displayName/avatar/计数），上游仍按旧字段解析导致全空。"""
    out = json.loads(_orig_get_my_profile(self))
    base = (((out.get("raw") or {}).get("data") or {}).get("module") or {}).get("base") or {}
    profile = out.setdefault("profile", {})
    if base:
        profile["nick"] = profile.get("nick") or base.get("displayName")
        profile["avatar_url"] = profile.get("avatar_url") or base.get("avatar")
        for src, dst in _NAV_COUNTS.items():
            if src in base:
                profile[dst] = base[src]
    if not profile.get("user_id"):
        jar = dict(kv.split("=", 1) for kv in up._load_cookie_str().split("; ") if "=" in kv)
        profile["user_id"] = jar.get("unb") or None
    return _xat._dump(out)


_xat.XianYuApiTools.get_my_profile = _profile_from_nav


for _tool in list(mcp._tool_manager._tools.values()):
    if _tool.name != "login_xianyu":
        _with_login_hint(_tool)


if __name__ == "__main__":
    up.main()
