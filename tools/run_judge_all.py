# -*- coding: utf-8 -*-
"""把判据报非 0 的**所有项目**跑一遍 LLM 判定。"""
import io, json, os, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import llm_judge as J

recs = J.load_recs()
repos = sorted(k for k, v in recs.items()
               if v["cells"]["unauth_endpoint"]["n"] > 0)
print("待判项目 %d 个" % len(repos))
J.judge_batch(repos, out_tag="llm_verdict")
