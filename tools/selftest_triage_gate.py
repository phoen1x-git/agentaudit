# -*- coding: utf-8 -*-
"""立卷门槛的自测（`tools/triage_gate.py`）。

★ 为什么要这一套：门槛的每一条都可能**静默放行**或**静默误挡**，两者都不会报错。
  实测踩过两次：①只比对完整 sink 名 → `subprocess.run` 一条都匹配不上，853 条被误挡；
  ②`os.path.join` 不在清单里 → 路径穿越类候选全被当成"进攻面弱"。
  这两次都是跑真实数据才发现的，所以拿 8 档把行为钉住。
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tools'))

import triage_gate as G          # noqa: E402
from core.finding import Finding  # noqa: E402

n_pass = n_fail = 0


def rec(name: str, ok: bool, detail: str = '') -> None:
    global n_pass, n_fail
    if ok:
        n_pass += 1
        print('  OK   %s' % name)
    else:
        n_fail += 1
        print('  FAIL %s   %s' % (name, detail))


def mk(**kw) -> Finding:
    base = dict(project='p', rule='k/s', sink_uri='app.py', sink_line=10,
                sink_func='eval', src_root='/tmp/x')
    base.update(kw)
    return Finding(**base)


HTTP = {'kind': 'http', 'exposure': 'high', 'reach': '任何能连到这个端口的人', 'who': '网络上的任何人'}
LIB = {'kind': 'library', 'exposure': 'low', 'reach': '只有显式 import 的调用方', 'who': '开发者'}
SRC_UP = [{'i': 0, 'kind': 'param', 'src_file': 'a.py', 'src_line': 3, 'src_text': 'request', 'arg_text': 'x'}]
SRC_LOCAL = [{'i': 0, 'kind': 'local', 'arg_text': 'lit'}]

print('立卷门槛自测 —— 14 档')

# 1. http + 危险动作 + 有上游 → 立案
g = G.gate(mk(entry_profile=HTTP, arg_sources=SRC_UP))
rec('http + eval + 追到上游 → 立案', g['pass'] is True, str(g))

# 2. 库模块、没有上游证据 → 挡在第②条（没有可达入口）
g = G.gate(mk(entry_profile=LIB, arg_sources=[]))
rec('库模块无上游 → 挡在 external_reach',
    g['pass'] is False and g['checks'].get('external_reach') is False, str(g['checks']))

# 3. 测试文件 → 挡在第①条
g = G.gate(mk(sink_uri='tests/test_app.py', entry_profile=HTTP, arg_sources=SRC_UP))
rec('测试文件不立案', g['pass'] is False and g['checks'].get('attack_surface') is False, str(g['checks']))

# 4. os.path.join 算进攻面（★ 末段 join 不能误伤 str.join）
rec('os.path.join 算进攻面', G._sink_matches('os.path.join') is True, '')
rec('str.join 不算进攻面', G._sink_matches('str.join') is False, '')
rec('subprocess.run 算进攻面', G._sink_matches('subprocess.run') is True, '')

# 4b. ★ 接收者丢了（`Attribute.join`）→ 只认源码行里的全名
rec('Attribute.join + 源码含 os.path.join → 算进攻面',
    G._sink_matches('Attribute.join', 'file_path = os.path.join(static_dir, path)') is True, '')
rec('Attribute.join + 源码是 "".join → 不算',
    G._sink_matches('Attribute.join', 'sep = "".join(parts)') is False, '')
rec('Attribute.exec + 源码是正则 exec → 不算（不许凭末段放行）',
    G._sink_matches('Attribute.exec', 'm = TYPED_ID.exec(task.content_id)') is False, '')

# 5. http + 只有 local 来源 → 第③条**判不了**（None），不是判否
#    ★ web 入口的值由框架从请求里取，CodeQL 追不到，标 local 是必然的；
#      把"追不到"记成"确实没有上游"，会让统计把缺数据读成没洞（实测 19 条 http 全中）。
g = G.gate(mk(entry_profile=HTTP, arg_sources=SRC_LOCAL))
rec('http 只有 local 来源 → upstream_traced 记为判不了（None）',
    g['pass'] is False and g['checks'].get('upstream_traced') is None, str(g['checks']))

# 5b. library + 只有 local 来源 → 这一档**能**判否（库没有框架注入这回事）
g = G.gate(mk(entry_profile=LIB, arg_sources=SRC_LOCAL))
rec('library 只有 local 来源 → upstream_traced 判否',
    g['checks'].get('upstream_traced') is False, str(g['checks']))

# 6. src_root 为空 → 形态 unknown，理由要说清「为什么不知道」
g = G.gate(mk(src_root='', entry_profile={}, arg_sources=SRC_UP))
rec('缺 src_root 时理由点明是 src_root 为空',
    g['pass'] is False and any('src_root 为空' in r for r in g['reasons']), str(g['reasons']))

# 7. unknown 形态不算通过（不许默认成 library 也不算默认成 http）
g = G.gate(mk(entry_profile={'kind': 'unknown'}, arg_sources=SRC_UP))
rec('unknown 形态不放行', g['pass'] is False, str(g['checks']))

# 8. cli 形态：可达性由上游兜（只有 arg_sources 才能救它）
g_ok = G.gate(mk(entry_profile={'kind': 'cli', 'exposure': 'low'}, arg_sources=SRC_UP))
g_no = G.gate(mk(entry_profile={'kind': 'cli', 'exposure': 'low'}, arg_sources=[]))
rec('cli 有上游→立案 / 无上游→挡', g_ok['pass'] is True and g_no['pass'] is False,
    '%s / %s' % (g_ok['checks'], g_no['checks']))

print('-' * 60)
print('结果：%d 通过 / %d 失败' % (n_pass, n_fail))
sys.exit(1 if n_fail else 0)
