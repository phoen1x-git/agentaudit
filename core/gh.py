"""内核 · GitHub API 最小客户端（零依赖）。

★ 上游核实（upstream）和目标健康门（gate）都要用，所以只放一份。
★ 用标准库 urllib：项目里不能引入外部依赖（要能直接跑）。
★ 明确**不用系统代理** —— 本机代理会让请求 5 次重试 × 超时，磨死人。
"""
from __future__ import annotations

import http.client
import json
import os
import socket
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

API = "https://api.github.com"
# ★ GitHub token 从**文件**读：不硬编码、不进版本库。
#   设环境变量 `GITHUB_KEY_FILE=/path/to/github.txt`，
#   或把 token 写进 `~/.github_token`。
KEY_FILE = os.environ.get("GITHUB_KEY_FILE") or str(Path.home() / ".github_token")

# ★★ 本机 hosts 里有 `127.0.0.1 api.github.com`（还有 github.com / raw.githubusercontent.com
#    等一串）——那是某个"屏蔽 github"的 hosts 列表留下的。它会让所有请求连到 127.0.0.1，
#    表现为「网络不通」，而 codeload.github.com 不在表里所以照常可达。
#    → 这里做**自动绕行**：若系统解析把 host 解析成回环地址，就用 DoH 取真 IP、按 IP 连，
#      但 TLS 的 SNI/Host 仍用原域名（证书照常校验）。环境变量 AF_GH_DOH=0 可关掉。
_DOH = os.environ.get("AF_GH_DOH", "https://223.5.5.5/resolve")
_LOOPBACK = {"127.0.0.1", "::1", "0.0.0.0"}


def _resolves_to_loopback(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except Exception:
        return True                           # 解析不了，也走 DoH 兜底
    addrs = {i[4][0] for i in infos}
    return bool(addrs) and addrs <= _LOOPBACK


def _doh_ip(host: str, timeout: float = 8.0) -> str | None:
    """用 DoH 拿真实 A 记录（绕开本地 hosts）。"""
    if os.environ.get("AF_GH_DOH", "https://223.5.5.5/resolve") == "0":
        return None
    try:
        req = urllib.request.Request(f"{_DOH}?name={host}&type=A",
                                     headers={"accept": "application/dns-json"})
        op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with op.open(req, timeout=timeout) as r:
            j = json.loads(r.read().decode("utf-8", "replace"))
        for a in j.get("Answer", []):
            if a.get("type") == 1 and a.get("data"):
                return a["data"]
    except Exception:
        pass
    return None


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    """把指定 host 的 TCP 连接指到固定 IP，TLS 仍按原域名握手（证书照验）。"""

    def __init__(self, pin: dict[str, str]):
        super().__init__()
        self.pin = pin

    def https_open(self, req):
        host = urllib.parse.urlsplit(req.full_url).hostname or ""
        ip = self.pin.get(host)
        if not ip:
            return self.do_open(http.client.HTTPSConnection, req)

        class _Conn(http.client.HTTPSConnection):
            def connect(self):
                self.sock = socket.create_connection((ip, self.port), self.timeout)
                if self._tunnel_host:                      # 理论上不会走到
                    self._tunnel()
                self.sock = self._context.wrap_socket(
                    self.sock, server_hostname=host)

        return self.do_open(_Conn, req)


def _opener_for(url: str):
    """构造 opener；若目标 host 被 hosts 黑洞，则加一个「按真 IP 连」的处理器。"""
    pin: dict[str, str] = {}
    host = urllib.parse.urlsplit(url).hostname or ""
    if host and _resolves_to_loopback(host):
        ip = _doh_ip(host)
        if ip:
            pin[host] = ip
    handlers = [urllib.request.ProxyHandler({})]
    if pin:
        handlers.append(_PinnedHTTPSHandler(pin))
    return urllib.request.build_opener(*handlers)


def token() -> str:
    p = Path(KEY_FILE)
    if not p.exists():
        raise SystemExit(
            f"找不到 GitHub token 文件：{KEY_FILE}\n"
            "  ⇒ 设环境变量 GITHUB_KEY_FILE 指向你的 token 文件，"
            "或把 token 写进 ~/.github_token")
    return p.read_text(encoding="utf-8").strip()


def get(url: str, raw: bool = False, tok: str | None = None) -> tuple[int, str]:
    tok = tok or token()
    hdrs = {
        "Authorization": "Bearer " + tok,
        "Accept": "application/vnd.github.raw" if raw else "application/vnd.github+json",
        "User-Agent": "af-kernel",
    }
    req = urllib.request.Request(url, headers=hdrs)
    opener = _opener_for(url)
    try:
        with opener.open(req, timeout=60) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")[:300]
    except Exception as e:
        return 0, f"{type(e).__name__}: {e}"


def get_json(url: str, tok: str | None = None):
    code, body = get(url, tok=tok)
    if code != 200:
        return None
    try:
        return json.loads(body)
    except Exception:
        return None
