# -*- coding: utf-8 -*-
"""★★★ 旋钮三 · Step 3：三档出口分类 —— 把「职责内出口」这条判据做出来

═══ 为什么这一步是旋钮三能不能用的关键 ═══
Step 2 的实测结果：
```
真外泄通道3 处 / not_channel 90 处 / needs_human 4 处   （精确率 3.1%）
```
★ 而人工核实发现那3 处 `real_channel` **全部是「功能本身就是这个出口」**：
  · `websocket_invoker.py` → 它的职责就是往用户配置的 endpoint 发数据
  · `slack_adapter.py`     → 它的职责就是往频道发消息
  · `task_notification.py` → 它的职责就是发任务通知邮件

★★ 所以真正缺的不是「更长的清单」，而是**第三档**：
```
① 职责内出口   这个出口就是这个功能的用途 → ★ 不是漏洞
② 配置型外泄   数据外部可控，但目标写在配置里 → low/medium
③ ★ 可控外泄数据外部可控 **且** 目标外部可指定 → high/medium
```
没有①，90 处噪声会一直灌进人工。

═══ 这一版补什么证据 ═══
Step 2 那4 处 `needs_human` 卡在**同一个点**：
「目标地址从哪来」。
→ 补抓「目标变量的来源链」：
  ① 目标变量名（url/endpoint/recipient/channel…）
  ② 这个变量在函数里怎么来的（形参 / 从配置读 / 常量 / 从请求取）
  ③ ★ 请求里有没有对应的入参能改它
"""
import io
import json
import os
import re
import sys
from collections import Counter

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ast
import llm_client as LC
import llm_judge as J
import recheck

POOL = J.POOL
OUT = os.path.join(POOL, "knob3_verdict2.json")

# ★ 目标变量的形态 —— 决定「目标能不能被外部改」
TARGET_SHAPE = {
    "from_config": re.compile(
        r"(from\s+(self\.)?(config|settings|cfg)\b|"
        r"\b(load|get|read)_\w*config|settings\.\w+|config\.\w+|"
        r"getenv|environ|os\.env)", re.I),
    "hardcoded": re.compile(
        r"(https?://[\w.-]+|[\w.-]+@[\w.-]+\.\w+|"
        r"\"[^\"]{4,}\"|'[^']{4,}')", re.I),
    "from_request": re.compile(
        r"(request\.|req\.|params|query|payload|body|json_body|"
        r"message\.text|args\.|kwargs)", re.I),
    "from_func_arg": re.compile(r"^\s*(async )?def \w+\([^)]*\)|self\.\w+", re.I),
}
TARGET_VAR = re.compile(
    r"\b(\w*(url|uri|endpoint|webhook|recipient|to_addr|address|channel|"
    r"host|domain|token|chat_id|room)\w*)\b", re.I)


def target_chain(fmap, hit):
    """★ 追「目标变量从哪来」—— 这是职责内 vs 可控外泄的分水岭。"""
    fp = hit["_file"]
    src = fmap.get(fp, "")
    if not src:
        return None
    try:
        tree = ast.parse(src)
    except Exception:
        return None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
           and node.lineno <= hit["_line"] <= (getattr(node, "end_lineno",
                                                   node.lineno) or node.lineno):
            try:
                body = ast.unparse(node)
            except Exception:
                return None
            # ★ 找出所有像「目标」的变量名
            tvars = sorted(set(m.group(1) for m in
                               TARGET_VAR.finditer(body)))[:8]
            # ★ 每个目标变量的赋值形态
            shapes = {}
            for v in tvars:
                hits = []
                for mm in re.finditer(r"(?m)^[^#\n]*\b%s\b\s*=" % re.escape(v), body):
                    seg = mm.group(0)[:120]
                    if TARGET_SHAPE["from_request"].search(seg):
                        hits.append("from_request")
                    elif TARGET_SHAPE["from_config"].search(seg):
                        hits.append("from_config")
                    elif TARGET_SHAPE["hardcoded"].search(seg):
                        hits.append("hardcoded")
                    else:
                        hits.append("unknown")
                if hits:
                    shapes[v] = hits[:4]
            # ★ 函数签名（形参 = 可能被外部传）
            args = [a.arg for a in node.args.args + node.args.kwonlyargs]
            arg_targets = [a for a in args
                           if TARGET_VAR.search(a)]
            return {"func": node.name, "args": args[:14],
                    "arg_targets": arg_targets, "tvars": tvars,
                    "shapes": shapes, "body": body.splitlines()[:60]}
    return None


RUBRIC_K3B = """你是一个 Agent 项目「出口类型」的判定员。

★ 上一轮已经确认：这个出口点**确实会把数据发出去**。
   这一轮要判的是**更关键的一件事**：

   # ★★★ 这个出口「是干什么用的」？

分三档（★ 这是判定的核心，不要判成「有没有漏洞」）：

① ★ 职责内出口（duty）
   这个出口**就是这个功能的用途本身**。
   典型形态：
     · webhook/invoker 类：★ 它的定义就是「往用户配置的 endpoint 发数据」
     · 通知类：★ 它的定义就是「把任务/告警发给接收人」
     · 适配器类（Slack/邮件/Webhook 适配器）：★ 它只干这一件事
   判据：★ 看**它所在类/函数的职责**——如果这个出口就是它存在的理由，
        那它不是漏洞（维护者会说「这就是它的功能」）。

② 配置型外泄（config_egress）
   数据是外部可控的，**但发送目标写在配置文件/环境变量里**，外部请求改不了。
   判据：目标变量来自 config/settings/env/常量字符串。

③ ★ 可控外泄（controllable_egress）
   数据外部可控，★ **且发送目标也外部可指定**
   （endpoint/url/channel/recipient 来自请求参数或用户输入）。
   判据：目标变量出现在函数形参里，或从 request/query/payload 取。

★★ 最容易搞错的是①：
   「用户配了一个 Webhook 地址然后往里发数据」——
   ★ 这个 Webhook invoker 的**职责就是干这个**，
   所以即使目标外部可指定，它仍然是①，而不是③。
   ★★ 区分的关键不是「目标能不能改」，而是
      「★ 这个发送行为是不是该组件存在的目的」。

输出 JSON：
{
  "duty_of_component": "一句话：这个组件/函数是干什么的",
  "is_duty_of_component": "yes|no|unclear",
  "duty_evidence": "一句话，引用类名/函数名/docstring",
  "target_variable": "url/endpoint/channel 等目标变量名，或 none",
  "target_source": "request|config|env|hardcoded|param|unclear",
  "target_source_evidence": "一句话",
  "verdict": "duty|config_egress|controllable_egress|needs_human",
  "confidence": 0.0-1.0,
  "one_line": "一句话结论"
}

★ 信息不足就给 needs_human 并降低 confidence，
  **不要为了给答案而硬选一档**。"""


def main():
    d1 = json.load(open(os.path.join(POOL, "knob3_verdict.json"),
                        encoding="utf-8"))
    # ★ 三类都重新判：不只重判 needs_human，
    #   因为 Step 2 的 real_channel（那 3 处）也需要用新标准复核
    todo = [v for v in d1.values()
            if v.get("verdict") in ("needs_human", "real_channel")]
    print("待用新标准复核 %d 处（Step2 的 needs_human + real_channel）" % len(todo))

    done = json.load(open(OUT, encoding="utf-8")) if os.path.exists(OUT) else {}
    cost0 = LC.USAGE.cny
    for v in todo:
        repo = v["_repo"]
        key = "%s|%s|%d|%s" % (repo, v["_file"], v["_line"], v["_cat"])
        if key in done:
            continue
        # ★ branch 可能没存（Step 2 的输出没带_branch）→ 退回批次记录里查
        #   ★ 这是今天第二次栽在「branch」上（agentUniverse 在 master）。
        br = v.get("_branch")
        if not br:
            recs = J.load_recs()
            br = (recs.get(repo, {}).get("branch") or "main")
            v["_branch"] = br
        fmap, _n, _m = recheck.cache_files(repo, br)
        if not fmap:
            alt = "master" if br == "main" else "main"
            fmap, _n, _m = recheck.cache_files(repo, alt)
            if fmap:
                v["_branch"] = alt
                br = alt
        if not fmap:
            print("  ! %s 取不到源码（branch=%s）" % (repo.split("/")[-1][:20], br))
            continue
        chain = target_chain(fmap, v)
        if not chain:
            print("  ! %s 定位不到函数" % repo.split("/")[-1][:20])
            continue

        chain_txt = ("函数：%s\n形参：%s\n"
                     "★ 像「目标」的变量及其赋值来源：\n%s\n\n"
                     "【函数体】\n%s"
                     % (chain["func"], ", ".join(chain["args"]),
                        "\n".join("  %s ← %s" % (k, v2)
                                  for k, v2 in chain["shapes"].items()) or "  （没找到）",
                        "\n".join("  " + b[:104] for b in chain["body"])))
        user = ("【项目】%s\n【出口点】%s:%d（分类 %s）\n  代码：%s\n\n"
                "【★ 目标变量的来源追踪】\n%s\n\n"
                "【上一轮的判定（供参考，可能有误）】\n"
                "  data_source=%s target_controllable=%s\n\n"
                "请按三档判定：这是「职责内出口」「配置型外泄」还是「可控外泄」？"
                % (repo, v["_file"], v["_line"], v["_cat"], v["_code"],
                   chain_txt, v.get("data_source"), v.get("target_controllable")))
        try:
            r = LC.ask_json(RUBRIC_K3B, user, tag="knob3b", max_tokens=3600)
        except Exception as e:
            print("  ★ %s 失败 %s" % (repo.split("/")[-1][:20], str(e)[:40]))
            continue
        r["_repo"] = repo
        r["_file"] = v["_file"]
        r["_line"] = v["_line"]
        r["_cat"] = v["_cat"]
        r["_prev"] = v.get("verdict")
        done[key] = r
        json.dump(done, open(OUT, "w", encoding="utf-8"),
                  ensure_ascii=False, indent=1)
        print("  %-22s %-10s %-12s → %-20s %s"
              % (repo.split("/")[-1][:22], v["_cat"], v.get("verdict"),
                 r.get("verdict"), (r.get("one_line") or "")[:44]))

    print()
    print("复核 %d 处，花费 %.4f 元" % (len(done), LC.USAGE.cny - cost0))
    print("verdict: %s" % dict(Counter(x.get("verdict")
                                       for x in done.values())))
    print()
    print("★ 关键对照 —— Step2 判real_channel 的那 3 处，新标准下是什么：")
    for k, x in done.items():
        if x.get("_prev") == "real_channel":
            print("  %-22s %-10s → %-22s 职责=%s"
                  % (x["_repo"].split("/")[-1][:22], x["_cat"],
                     x.get("verdict"), (x.get("duty_of_component") or "")[:50]))


if __name__ == "__main__":
    main()