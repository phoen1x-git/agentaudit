# -*- coding: utf-8 -*-
"""★★★ 旋钮四 · 第二层：职责内判定（上一版只做了上半程）

═══ 为什么必须补这一层 ═══
`docs/68` 里我报了「精确率 26%」，但那是**上半程**的数字：
```
第一层（已做）：入口有真外部数据 + 流到危险操作 + 流闭合  → 11/43 = 26%
第二层（★ 本文件）：这个「写文件」是该功能的职责吗？         → 预计再降不少
```
★ 旋钮三已经证明这一层是决定性的（7 处全改判 duty）。

═══ 旋钮四特有的判断难点 ═══
旋钮三的「职责内」很好判（webhook/通知/Slack 适配器一眼看出）。
★ 但旋钮四的「文件上传 → 写文件」**最难判**，因为：
  · 「上传文件存起来」**本身就是**文件上传端点的职责 → 多数是职责内
  · ★ 但「上传 tar 包解到 home」→ 有白名单 → 看白名单严不严
  · ★★最关键：**有没有「这个入口本不该出现在这里」的信号**
    例如：查询接口里接受 tar 上传、健康检查里接受文件

★ 所以这一层要问的不是「这功能合理吗」，而是
  ★ 「★ 这个端点的声明用途（路由/docstring）和它的实际危险操作一致吗」
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
OUT = os.path.join(POOL, "knob4_duty.json")

RUBRIC_K4DUTY = """你在判一个 Agent 项目的「上传端点」：**它危险吗？**

★ 前一轮已经确认：它**确实**接收外部上传内容，并**确实**写到了某个地方。
   这一轮只问一件事：**这正常吗？**

═══ 判定的核心问题 ═══
**这个端点做这件事，是它的本职工作吗？**

判据（★ 从松到严，逐档）：
① ★ 完全职责内
   · 文件上传端点把上传的文件存到存储/落盘
   · 附件上传、头像上传、知识库文档上传
   · ★ 端点名字/路由/docstring 就写着 upload/store/add_attachment
   → **不是漏洞**

② 职责内但有防护
   · 同上，但做了路径白名单 / 文件名清洗 / 类型限制 / 大小限制
   → ★★ **不是漏洞，而且实现质量高，要明确表扬**
   ★ 判据：有没有 `relative_to()` / 白名单 / `basename()` /
     `secure_filename` / 后缀白名单 / `isalnum` / 大小检查

③ ★ 不确定：声明的用途和实际做的事不一致
   · 端点叫「查询/健康检查/预览」，但接受文件上传并落盘
   · 或者：路由完全看不出是上传接口
   → needs_human

④ 不是职责内（真可疑）
   · 上传内容被**当成命令/代码执行**
   · 上传的**路径**可控（写到目标目录之外）
   · 上传内容被**拼进 prompt 当 system 指令**
   · 上传的 tar/zip **解包**且路径校验不严
   → ★ 这是真问题

★★ 最容易搞错的：
  · 「写文件」本身不是问题 → ★ 存文件就是上传端点的活
  · ★ 但「解包」要另看 —— tar/zip 解包是路径穿越的重灾区，
    要看有没有逐条校验（`relative_to` / 拒绝 `..` / 拒绝绝对路径）

输出 JSON：
{
  "declared_purpose": "一句话，这个端点声称自己是干什么的（据路由名/docstring/函数名）",
  "actual_behavior": "一句话，它实际做了什么危险操作",
  "duty_match": "yes|no|unclear",
  "protection": "none|whitelist|basename|suffix|size|multi",
  "protection_evidence": "一句话，引用具体防护代码；没有就写 none",
  "is_unpack": "yes|no",          ★ 有没有解包（tar/zip）
  "verdict": "duty|protected|suspicious|needs_human",
  "severity": "none|low|medium|high",
  "confidence": 0.0-1.0,
  "evidence": "一句话，引用具体代码",
  "one_line": "一句话结论"
}

判定尺度：
- duty        职责内（①）
- protected   职责内但有防护（②）→ ★ 明确不是漏洞
- suspicious  用途与实际不符，或危险的是路径/解包/执行（④）
- needs_human 看不出声明用途，或防护看不清
★ suspicious 才算真问题；duty 和 protected 都不是。"""


def main():
    src = os.path.join(POOL, "knob4_verdict.json")
    d1 = json.load(open(src, encoding="utf-8"))
    # ★ 只重判 real_taint（第一层判真的），benign 不用再判
    todo = [v for v in d1.values() if v.get("verdict") == "real_taint"]
    print("第一层判 real_taint 的%d 处，逐个补职责判定" % len(todo))

    done = json.load(open(OUT, encoding="utf-8")) if os.path.exists(OUT) else {}
    cost0 = LC.USAGE.cny
    for v in todo:
        repo = v["_repo"]
        key = "%s|%s|%d" % (repo, v["_file"], v["_line"])
        if key in done:
            continue
        br = v.get("_branch")
        if not br:
            recs = J.load_recs()
            br = (recs.get(repo, {}).get("branch") or "main")
        fmap, _n, _m = recheck.cache_files(repo, br)
        if not fmap:
            alt = "master" if br == "main" else "main"
            fmap, _n, _m = recheck.cache_files(repo, alt)
        if not fmap:
            print("  ! %s 取不到源码" % repo.split("/")[-1][:20])
            continue
        src_txt = fmap.get(v["_file"], "")
        body = []
        if src_txt:
            try:
                for n in ast.walk(ast.parse(src_txt)):
                    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                       and n.lineno == v["_line"]:
                        body = ast.unparse(n).splitlines()[:70]
                        break
            except Exception:
                pass
        # ★ 把危险操作那一段的上下文也带上（解包/路径拼接常在下面几行）
        L = (src_txt or "").splitlines()
        extra = ["%5d| %s" % (i + 1, L[i][:110])
                 for i in range(max(0, v["_line"] - 1),
                                min(len(L), v["_line"] + 40))]

        user = ("【项目】%s\n【端点】%s:%d\n  签名：%s\n  入口类型：%s\n\n"
                "【第一层判定（供参考，可能有误）】\n"
                "  外部数据=%s 到危险=%s 流闭合=%s\n  危险操作证据：%s\n\n"
                "【函数完整源码】\n%s\n\n"
                "【危险操作附近 40 行】\n%s\n\n"
                "请判定：这个上传端点做这件事是它的职责吗？"
                % (repo, v["_file"], v["_line"], v.get("_sig", ""),
                   json.dumps(v.get("_kinds", {}), ensure_ascii=False),
                   v.get("has_external_data"), v.get("reaches_danger"),
                   v.get("flow_closed"), (v.get("danger_evidence") or "")[:120],
                   "\n".join("  " + x[:110] for x in body),
                   "\n".join("  " + x for x in extra[:40])))
        try:
            r = LC.ask_json(RUBRIC_K4DUTY, user, tag="knob4duty", max_tokens=3600)
        except Exception as e:
            print("  ★ %s 失败 %s" % (repo.split("/")[-1][:20], str(e)[:40]))
            continue
        r["_repo"] = repo
        r["_file"] = v["_file"]
        r["_line"] = v["_line"]
        r["_first_verdict"] = "real_taint"
        done[key] = r
        json.dump(done, open(OUT, "w", encoding="utf-8"),
                  ensure_ascii=False, indent=1)
        print("  %-22s %-14s %-12s %-7s %s"
              % (repo.split("/")[-1][:22], v["_file"].split("/")[-1][:14],
                 r.get("verdict"), r.get("severity"),
                 (r.get("one_line") or "")[:44]))

    print()
    print("复核 %d 处，花费 %.4f 元" % (len(done), LC.USAGE.cny - cost0))
    c = Counter(x.get("verdict") for x in done.values())
    print("verdict: %s" % dict(c))
    n = len(done)
    sus = c.get("suspicious", 0)
    print()
    print("★ 两层过滤后的精确率：%d/%d = **%.1f%%**"
          % (sus, n, 100.0 * sus / max(1, n)))
    print("  （第一层是 %d/%d = %.1f%%）"
          % (len(todo), len(todo), 100.0))
    print()
    print("★ suspicious 的（这才是真问题）:")
    for k, x in done.items():
        if x.get("verdict") == "suspicious":
            print("  %-22s %-24s %-7s %s"
                  % (x["_repo"].split("/")[-1][:22],
                     x["_file"].split("/")[-1][:24], x.get("severity"),
                     (x.get("evidence") or "")[:70]))
    print()
    print("★ protected 的（实现规范，明确不是洞）:")
    for k, x in done.items():
        if x.get("verdict") == "protected":
            print("  %-22s %-24s %s"
                  % (x["_repo"].split("/")[-1][:22],
                     x["_file"].split("/")[-1][:24],
                     (x.get("protection_evidence") or "")[:66]))


if __name__ == "__main__":
    main()