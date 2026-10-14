# -*- coding: utf-8 -*-
"""★ DeepSeek 客户端 —— 整个「LLM 判定层」的地基。

★★ 为什么必须是基础设施而不是脚本
------------------------------------------------
① **缓存**：同样的输入不重复调。同一个判定重跑 3 遍不该花 3 遍的钱。
② **成本记账**：每次调用记 token 数和折算金额，跑完能报「308 处花了 X 元」。
   ★ 这是能不能做成论文的关键之一 —— 论文要报「检出率」，
     如果「用 LLM 判定」这一环的成本不可控，这个方法就不可复现。
③ **重试 + 退避**：网络抖动不该让整批失败。
④ **判定不可复现的防护**：temperature=0 + 记录原始响应。

★ 为什么不直接用 openai 官方包：DeepSeek 兼容 OpenAI 格式但没有官方 SDK，
  而项目里 `ast_criteria` 等模块**不能引入外部依赖**（要能直接跑）。
  所以用标准库 urllib —— 零依赖。
"""
import hashlib
import io
import json
import os
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))

# ============ 配置 ============
# ★ key 从**文件**读，**不硬编码、不进版本库**。
#   设环境变量 `DEEPSEEK_KEY_FILE=/path/to/deepseek.txt`，
#   或把 key 写进 `~/.deepseek_key`。
KEY_FILE = os.environ.get("DEEPSEEK_KEY_FILE") or os.path.expanduser("~/.deepseek_key")

# ============ ★★ 连续失败熔断（2026-10-12 加）============
# 起因：一次**余额/额度**故障被当成普通网络抖动 → 扫描白跑 1 小时多、判定行全变 `error`
#       （实测：`HTTP 405` 空响应体从第 213 个候选起间歇出现，之后 76 条失败）。
# ★ 规则：连续失败到阈值就**中止**并说出原因，绝不继续烧时间。
#   任何原因（余额 / 额度 / 网络 / 网关）都算 —— 因为"连续 N 次都不成功"本身就是结论。
_CONSEC_FAIL = 0
_CONSEC_FAIL_LIMIT = 8


def _bump_fail() -> None:
    global _CONSEC_FAIL
    _CONSEC_FAIL += 1
    if _CONSEC_FAIL >= _CONSEC_FAIL_LIMIT:
        raise SystemExit(
            "★ 连续 %d 次 LLM 调用失败 —— 先停下来查原因（余额 / 额度 / 网络），"
            "别继续烧时间。判据提醒：余额不足**会以不同状态码出现**"
            "（402 带 body，或 405 带空 body）。" % _CONSEC_FAIL)


def _reset_fail() -> None:
    global _CONSEC_FAIL
    _CONSEC_FAIL = 0


# ============ ★★ 单次运行的「防失控」上限（2026-10-12 加，当天改口径）============
# 口径变更（用户 2026-10-12 15:05）：
#   「**不要因为钱限制自己的能力和事情**，也不要等到我批准花多少钱你再做。
#     你唯一要做的，就是**尽量避免没意义的浪费**。」
# → 所以这个上限**不是"预算闸"，是"失控保险丝"** —— 防的是 bug 导致的无限调用
#   （例：判定失败却一直重试、循环里反复打同一个 payload），**不是**限制正常批次。
#   · 默认 **30.0 元**：远高于任何单批的正常成本（最大的一批 890 条 ≈ 14 元），
#     且远低于余额（用户 15:05 充值后余额 100 元）→ 正常干活碰不到，失控时能兜住。
#   · 到限硬停并报数（**不是**要批准，是**报警**：说明有异常，需要查）。
#   · `AF_LLM_MAX_CNY=0` = 完全不设（调试用）。
# ★ 真正要守的纪律不是"少花钱"，是"**别把同一件事做两遍**"——见 `docs/191` §五。
MAX_CNY = float(os.environ.get("AF_LLM_MAX_CNY", "30.0") or 0)
_RUN_CNY = 0.0


def _check_budget(cny: float) -> None:
    global _RUN_CNY
    _RUN_CNY += float(cny or 0)
    if MAX_CNY > 0 and _RUN_CNY >= MAX_CNY:
        raise SystemExit(
            "★★ 本次运行花费 %.2f 元，已越过「防失控」上限 %.2f 元 → 硬停。\n"
            "   ★ 这**不是**预算问题，是**异常信号**：正常批次不该花这么多。\n"
            "     先查：① 是不是在重复判定同一批（缓存未命中？）② 是不是有循环/长重试\n"
            "   若确认正常、只是批特别大，显式抬高：AF_LLM_MAX_CNY=<更大的数>"
            % (_RUN_CNY, MAX_CNY))


BASE_URL = "https://api.deepseek.com"
MODEL = "deepseek-flash"   # ★ 实测 flash 与 pro 同质量但便宜 20%、快 2倍

# ★★★ 成本表（CNY / token）
#   深Seek 官方：输入 1元/百万token（缓存命中 0.02元）、输出 8元/百万token
#★★ 踩过的坑：单位是**每百万 token**，不是每千。
#   我第一版写 `1.0 / 1000.0`（=每千 1 元）→ **成本被高估 1000 倍**，
#   外推「308 处要 18元」其实是错的。
#   → 判定成本时**务必先验单位**：拿一次响应的 token 数 × 单价，
#     和扣款后的余额变化对一下。
PRICE = {
    "input_miss": 1.0 / 1000000.0,      # 1 元 / 百万 token
    "input_hit": 0.02 / 1000000.0,      # 缓存命中 0.02 元 / 百万
    "output": 8.0 / 1000000.0,          # 8 元 / 百万
}

CACHE_DIR = os.path.join(ROOT, "data", "llm_cache")
LOG_PATH = os.path.join(ROOT, "data", "llm_usage.jsonl")


# ============ 成本记账 ============
class Usage:
    """累计 token 与金额。★ 每批结束必须报出来。"""

    def __init__(self):
        self.calls = 0
        self.hit_cache = 0
        self.in_tok = 0
        self.out_tok = 0
        self.cached_tok = 0
        self.cny = 0.0

    def add(self, r):
        self.calls += 1
        u = r.get("usage") or {}
        self.in_tok += u.get("prompt_tokens", 0)
        self.out_tok += u.get("completion_tokens", 0)
        self.cached_tok += (u.get("prompt_cache_hit_tokens") or 0)
        self.cny += _last_cny(r)

    def report(self):
        return ("调用 %d 次（其中 %d 次命中本地缓存）\n"
                "  token：输入 %d（其中缓存命中 %d）/ 输出 %d\n"
                "  花费：%.4f 元（单次均值 %.5f 元）"
                % (self.calls, self.hit_cache, self.in_tok, self.cached_tok,
                   self.out_tok, self.cny,
                   (self.cny / self.calls) if self.calls else 0))


USAGE = Usage()


def read_key():
    if not os.path.exists(KEY_FILE):
        raise SystemExit(
            "找不到 key 文件 %s\n"
            "★ 别把 key 写进代码 —— 用环境变量 DEEPSEEK_KEY_FILE 指过去。" % KEY_FILE)
    with open(KEY_FILE, "r", encoding="utf-8") as f:
        return f.read().strip()


def _cache_path(tag, payload):
    h = hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()[:40]
    d = os.path.join(CACHE_DIR, tag)
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, h + ".json")


def chat(system, user, tag="default", max_tokens=1600,
         temperature=0.0, retries=3, use_cache=True):
    """调一次 DeepSeek。

    ★ temperature=0：判定要**可复现**。同一个输入两次跑要得到同一个结论，
      否则「检出率」这个数字每次都不一样。

    ★★ `deepseek-flash` / `deepseek-v4-pro` 都是**推理模型**：
       usage 里会有 `reasoning_tokens`，token 先花在思考上，
       正文还没写完就撞上 max_tokens → finish_reason="length"
       → **JSON 被截断，解析必然失败**。
       实测：max_tokens=1200 时 pro 只有 3/8 能出完整 JSON，
       flash 6/8。→ 所以默认给足，并自动识别截断重试。
    """
    payload = {"model": MODEL, "messages": [
        {"role": "system", "content": system},
        {"role": "user", "content": user}],
        "temperature": temperature, "max_tokens": max_tokens}

    cp = _cache_path(tag, payload)
    if use_cache and os.path.exists(cp):
        try:
            with open(cp, "r", encoding="utf-8") as f:
                r = json.load(f)
            USAGE.hit_cache += 1
            _reset_fail()          # ★ 命中缓存也算"这次成功了"，熔断计数器归零
            return r
        except Exception:
            pass

    key = read_key()
    req = urllib.request.Request(
        BASE_URL + "/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer " + key})
    last = None
    for a in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=300) as resp:
                r = json.loads(resp.read().decode("utf-8"))
            # ★★ 输出被截断就把缓存文件删掉 —— 否则下次会一直拿到这段残缺内容
            if r["choices"][0].get("finish_reason") == "length":
                last = "finish_reason=length（输出被截断，JSON 不完整）"
                try:
                    os.remove(cp)
                except OSError:
                    pass
                if a < retries - 1:
                    # ★ 指数退避 + 翻倍 max_tokens
                    max_tokens = int(max_tokens * 1.8)
                    payload["max_tokens"] = max_tokens
                    req = urllib.request.Request(
                        BASE_URL + "/chat/completions",
                        data=json.dumps(payload).encode("utf-8"),
                        headers={"Content-Type": "application/json",
                                 "Authorization": "Bearer " + key})
                    continue
                raise RuntimeError(
                    "%s —— 这个模型是推理模型，thinking 需要更多 token。"
                    "解法：换 deepseek-flash（实测完成率明显更高），"
                    "或把 max_tokens 再加大" % last)
            USAGE.add(r)
            _reset_fail()          # ★ 成功一次就归零（熔断只针对"**连续**失败"）
            _check_budget(_last_cny(r))   # ★★ 花费硬上限：到限硬停并报数
            with open(cp, "w", encoding="utf-8") as f:
                json.dump(r, f, ensure_ascii=False, indent=1)
            os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
            with open(LOG_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "tag": tag, "model": MODEL,
                    "usage": r.get("usage", {}), "cny": round(_last_cny(r), 6),
                }, ensure_ascii=False) + "\n")
            return r
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8", "replace")[:300]
            except Exception:
                pass
            last = "HTTP %s %s" % (e.code, body)
            _bump_fail()                       # ★ 连续失败熔断
            # ★★ 余额 / 额度类：**不看状态码，看响应体**
            #    2026-10-12 实测：同一个"余额不足"会以 **402 带 body** 出现，
            #    也会以 **405 带空 body** 出现 → 原来只判 `402/403 + body 含 balance`
            #    会**漏掉 405 这个变体** → 护栏不触发 → 白烧一小时。
            low = body.lower()
            if e.code in (402, 403) or any(
                    k in low for k in ("insufficient", "balance", "quota", "exceeded")):
                raise SystemExit(
                    "★ 像是 DeepSeek 余额 / 额度用尽 —— 先充值或查额度，别继续烧时间：%s" % last)
            if a < retries - 1:
                time.sleep(2 * (a + 1))
        except Exception as e:
            last = "%s: %s" % (type(e).__name__, e)
            _bump_fail()                       # ★ 网络类失败也算
            if a < retries - 1:
                time.sleep(2 * (a + 1))
    raise RuntimeError("LLM 调用失败（重试 %d 次）：%s" % (retries, last))


def _last_cny(r):
    u = r.get("usage") or {}
    return (u.get("prompt_tokens", 0) * PRICE["input_miss"]
            + (u.get("prompt_cache_hit_tokens") or 0) * PRICE["input_hit"]
            + u.get("completion_tokens", 0) * PRICE["output"])


def _extract_json(txt):
    """从模型输出里把 JSON 挖出来。

    ★★★ 为什么不能直接 json.loads（10-07 实测踩了 4 次）
    --------------------------------------------------
    两个模型都是**推理模型**，实测输出有四种形态：
      ① 纯 JSON                    （最好情况）
      ② ```json ... ``` 围栏包裹
      ③ JSON 前后带解释文字
      ④ ★★ **尾部被 max_tokens 截断**—— 前面的字段是完整的、
         只是没写完最后的 `}`（实测 finish_reason="length"）

    ④ 这种最坑：肉眼看前面字段都对，但 json.loads 一定抛异常。
    → 所以先试「补上缺失的括号」再 parse —— 能救回绝大部分。

    ★ 顺序不能乱：围栏 → 裁剪 → 补括号 → parse
    """
    txt = (txt or "").strip()
    #② 剥围栏
    if txt.startswith("```"):
        txt = txt.split("```")[1]
        if txt.startswith("json"):
            txt = txt[4:]
        txt = txt.strip()
    # ③ 裁到第一个 { 与最后一个 }
    i, j = txt.find("{"), txt.rfind("}")
    if i >= 0 and j > i:
        txt = txt[i:j + 1]
    # ④ 尝试补齐（应对截断）
    for _ in range(3):
        try:
            return json.loads(txt)
        except Exception:
            # 补右括号
            opens = txt.count("{") - txt.count("}")
            brackets = txt.count("[") - txt.count("]")
            if opens > 0:
                txt += "}" * opens
            elif brackets > 0:
                txt += "]" * brackets
            else:
                break
    return None


def ask_json(system, user, tag="default", max_tokens=3600, **kw):
    """要 JSON 回答。

    ★ max_tokens 默认给到 3600 —— 推理模型的 thinking + 正文要一起算，
      给少了会被截断（实测 pro@1200 只有 3/8 能出完整 JSON）。
    """
    for a in range(2):
        r = chat(system + "\n\n★只输出一个 JSON 对象，不要任何解释文字、"
                        "不要代码围栏。", user, tag=tag,
                 max_tokens=max_tokens * (1 if a == 0 else 2), **kw)
        txt = r["choices"][0]["message"]["content"] or ""
        got = _extract_json(txt)
        if got is not None:
            return got
        if a == 0:
            continue
        raise ValueError("两次都不是合法 JSON，原文尾部：\n%s" % txt[-400:])


def self_test():
    """连通 + 缓存 + 成本记账 三件事一起验。"""
    print("=== 1. 连通性 ===")
    r = chat("你是一个只会回答 JSON 的助手。",
             '输出 {"ok": 1, "msg": "连通"}', tag="selftest")
    print("  回答:", r["choices"][0]["message"]["content"].strip()[:60])
    print("  usage:", json.dumps(r.get("usage"), ensure_ascii=False))

    print("\n=== 2. 缓存（第二次不该再花钱）===")
    before = USAGE.cny
    chat("你是一个只会回答 JSON 的助手。",
         '输出 {"ok": 1, "msg": "连通"}', tag="selftest")
    print("  第二次调用后新增花费: %.6f 元（应为 0）" % (USAGE.cny - before))
    print("  缓存命中次数:", USAGE.hit_cache)

    print("\n=== 3. JSON 解析（剥代码围栏）===")
    j = ask_json("你是一个只会回答 JSON 的助手。",
                  '输出 {"verdict": "not_vuln", "confidence": 0.9}', tag="selftest_json")
    print("  解析结果:", json.dumps(j, ensure_ascii=False))

    print("\n=== 4. 成本记账 ===")
    print("  " + USAGE.report())
    print("\n全部通过。")


if __name__ == "__main__":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                                  errors="replace")
    self_test()