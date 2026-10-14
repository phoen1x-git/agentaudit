# -*- coding: utf-8 -*-
"""★ 重跑被截断的那些处（推理模型 thinking 吃掉了 token）。

★★ 为什么这个必须做
------------------
`/api/all` 那处是**本项目最关键的一处** —— 两个模型都认为它可能是真漏洞，
而我的人工结论已经被证明是错的。**正因为它难判，thinking 才长**，
才撞上 max_tokens。

★ 所以「截断」不是随机故障，它**集中在难判的样本上** ——
   直接丢掉它们，等于系统性地丢掉最值得看的那部分。
   ★ 这是「用固定预算跑推理模型」的隐蔽陷阱：
     看起来是随机失败，实际是「难的就跑不出来」。
"""
import io
import json
import os
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import llm_client as LC
import llm_judge as J
import recheck

POOL = J.POOL
OUT = os.path.join(POOL, "llm_verdict.json")

# ★ 难判样本的特征：项目大 + 端点敏感。给更大的预算。
HARD = 12000


def main():
    done = json.load(open(OUT, encoding="utf-8")) if os.path.exists(OUT) else {}
    recs = J.load_recs()

    # 先找出「该判但没判成功」的
    missing = []
    for repo, rec in recs.items():
        for ev in (rec.get("evidence", {}).get("unauth_endpoint") or []):
            k = "%s|%s|%d" % (repo, ev["file"], ev["line"])
            if k not in done:
                missing.append((repo, ev))
    print("已判 %d / 应判 %d，待补 %d 处"
          % (len(done), len(done) + len(missing), len(missing)))
    if not missing:
        return

    by_repo = {}
    for repo, ev in missing:
        by_repo.setdefault(repo, []).append(ev)

    cost0 = LC.USAGE.cny
    for repo, evs in by_repo.items():
        rec = recs[repo]
        br = rec.get("branch") or "main"
        fmap, _n, _m = recheck.cache_files(repo, br)
        if not fmap:
            continue
        ctx = J.fmt_ctx(repo, J.build_context(rec, fmap))
        for ev in evs:
            k = "%s|%s|%d" % (repo, ev["file"], ev["line"])
            body = J.get_body(fmap, ev, maxlines=90)
            user = ctx + "\n\n" + J.fmt_item(ev, body) + \
                "\n\n请按三层判据判断这个命中是不是真漏洞。"
            try:
                # ★ 给 HARD 的预算，并且**换 tag** 避开被删掉的坏缓存
                r = LC.ask_json(J.RUBRIC, user, tag="llm_verdict_hard",
                                max_tokens=HARD)
            except Exception as e:
                print("  ★ %s 仍失败：%s" % (repo.split("/")[-1][:24],
                                          str(e)[:60]))
                continue
            r["_repo"] = repo
            r["_file"] = ev["file"]
            r["_line"] = ev["line"]
            r["_route"] = ev.get("route", "")
            done[k] = r
            json.dump(done, open(OUT, "w", encoding="utf-8"),
                      ensure_ascii=False, indent=1)
            print("  %-30s %-12s conf=%.2f %s"
                  % (repo.split("/")[-1][:30], r.get("verdict"),
                     r.get("confidence", 0), (r.get("one_line") or "")[:44]))

    print("\n补完，累计 %d 处" % len(done))
    print("本轮花费 %.4f 元，累计 %.4f 元" % (LC.USAGE.cny - cost0, LC.USAGE.cny))


if __name__ == "__main__":
    main()