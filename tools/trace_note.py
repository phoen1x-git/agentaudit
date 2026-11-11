"""内核 · 给一条候选自动写 trace_note。

★ 来由：`CASE-0003` §八 留的缺口 —— 「窗口之外我还手工看了什么」没有地方记。
  这件事以前只能人写，所以 15 条试填里 `guards` 装 0%、`arg_source` 零区分度。
  本模块把它变成可复现的三步：候选落在哪个函数 → 谁调用了它 → 实参对到形参上。

★ 口径（读的时候别越过去）：
  1. `core/source_index.py` 只证明【语法】。运行时派发、装饰器注册、猴子补丁，
     它一律不建模，`binding_scope` 里原话写着，本模块照抄进 `limits`。
  2. 调用方分三档，**只有前两档能当证据用**：
     strong = `lexical_binding` / `import_binding`（名字真解析到了这个定义）
     medium = `class_member_candidate` / `ambiguous_binding`（对到了但可能有多个目标）
     weak   = `name_only_candidate`（**同名猜测**，`call`/`forward` 这种通用名会放大到上百条）
  3. 索引不完整（超预算、超时、编码错）时 `coverage.complete` 为假，
     **不许**把 note 当成「仓库里就这些调用方」。
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.source_index import SearchBudget, SourceIndex, expression  # noqa: E402

SCHEMA = 'trace-note-v1'

STRONG = ('lexical_binding', 'import_binding')
MEDIUM = ('class_member_candidate', 'ambiguous_binding')
WEAK = ('name_only_candidate', 'unmodeled_container_or_dynamic_method')

FIXED_LIMITS = [
    '只看语法：运行时派发、装饰器注册、monkey patch、子类覆盖都不建模',
    '只索引 .py：模板、配置、JS/TS、proto 生成代码不在范围内',
    '调用方按名字解析，通用方法名（call / forward / run / get）会命中同名噪声，已单列 weak 档',
    '实参只对形参位置，*args / **kwargs 拆包时 binding_complete 为假',
]


def _tier(resolution: str) -> str:
    if resolution in STRONG:
        return 'strong'
    if resolution in MEDIUM:
        return 'medium'
    return 'weak'


def _jsonable(obj):
    """source_index 的部分结构里挂着 ast 节点，落 JSON 前要摘掉。"""
    if isinstance(obj, dict):
        return {k: _jsonable(v) for k, v in obj.items() if k != 'node'}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return str(obj)


def _excerpt(idx, rel, lo, hi, limit=8):
    try:
        block = idx.span(rel, lo, hi, anchor=lo, limit=limit)
    except Exception as exc:  # 取窗口失败不该让整条 note 崩
        return {'error': '%s: %s' % (type(exc).__name__, exc)}
    return block


def _fallback_name_scan(idx, enc, known_ids, excerpt_lines=8, max_items=12):
    """`callers()` 的补漏：按叶子名再扫一遍。

    ★ 为什么要补：`source_index.callers()` 只在 `resolution == unresolved` 时才把
      「没解析到 id」的调用收进 `_unresolved_calls`。可是基类方法被子类用 `self.x()` 调时，
      `resolve()` 返回的是 `([], 'class_member_candidate')` —— **id 为空但标签不是 unresolved**，
      于是调用被静默丢掉。实测：MetaGPT `ThoughtSolverBase.generate_thoughts` 在
      子类 `BFSSolver` / `DFSSolver` 里各被调一次（tot.py:173、196），`callers()` 返回 0。
    ★ 口径：这些行一律标 `via=fallback_name_scan`，且标签照抄 `resolve()` 的结论，
      不当成 strong。宁可少算，不能把同名当证据。
    """
    name = enc['name']
    # callers() 返回的是 {**call} 的副本，字典 id 对不上，但里面挂着同一个 ast 节点
    known = {id(c['node']) for c in known_ids if c.get('node') is not None}
    rows = []
    for call in idx.calls:
        if id(call['node']) in known:
            continue
        leaf = call['node'].func
        if isinstance(leaf, ast.Name):
            leaf_name = leaf.id
        elif isinstance(leaf, ast.Attribute):
            leaf_name = leaf.attr
        else:
            continue
        if leaf_name != name:
            continue
        ids, resolution = idx.resolve(call['file'], call['scope'], leaf)
        if enc['id'] in ids:
            continue
        row = {
            'resolution': resolution or 'name_only_candidate',
            'file': call['file'],
            'line': call['node'].lineno,
            'scope': call.get('scope', ''),
            'via': 'fallback_name_scan',
            'call_expression': None,
            'arguments': [],
            'bindings': [],
            'binding_complete': None,
            'excerpt': None,
        }
        try:
            described = idx.describe_call(call, enc)
            row['call_expression'] = described.get('expression')
            row['arguments'] = described.get('arguments', [])
            row['bindings'] = described.get('bindings', [])
            row['binding_complete'] = described.get('binding_complete')
            row['binding_scope'] = described.get('binding_scope', '')
        except Exception as exc:
            row['describe_error'] = '%s: %s' % (type(exc).__name__, exc)
        row['excerpt'] = _excerpt(idx, call['file'], call['node'].lineno, call['node'].end_lineno, excerpt_lines)
        rows.append(row)
        if len(rows) >= max_items:
            break
    return rows


def _raw_excerpt(path, line, radius=8, max_lines=20000):
    """不建索引，直接读源码窗口（给非 Python 文件用，只证明「这一行长这样」）。"""
    try:
        text = Path(path).read_text(encoding='utf-8', errors='replace')
    except OSError as exc:
        return {'error': '%s: %s' % (type(exc).__name__, exc)}
    lines = text.splitlines()
    line = int(line or 0)
    lo = max(1, line - radius)
    hi = min(len(lines), line + radius)
    return {'file': str(path).replace('\\', '/'), 'start_line': lo, 'end_line': hi,
            'total_lines': len(lines),
            'lines': [{'line': n, 'text': lines[n - 1]} for n in range(lo, hi + 1)]}


def build_note(root, rel, line, *, budget=None, max_weak=12, excerpt_lines=8, focus_files=()):
    """给 (root, rel, line) 生成一份 trace_note。返回可直接落 JSON 的 dict。"""
    started = time.monotonic()
    note = {
        'schema': SCHEMA,
        'target': {'root': str(root).replace('\\', '/'), 'file': rel.replace('\\', '/'), 'line': int(line or 0)},
        'status': 'ok',
        'enclosing': None,
        'callers': {'total': 0, 'strong': 0, 'medium': 0, 'weak': 0,
                    'by_resolution': {}, 'strong_calls': [], 'medium_calls': [], 'weak_calls': []},
        'local_inputs': [],
        'limits': list(FIXED_LIMITS),
        'coverage': {},
        'text': '',
    }
    root_path = Path(root)
    if not root_path.is_dir():
        note['status'] = 'root_not_found'
        note['text'] = '源代码根目录不存在：%s' % root
        return note

    rel = rel.replace('\\', '/')
    if not rel.lower().endswith('.py'):
        # 非 Python：索引器根本不收，硬跑只会给出「找不到函数」这种误导性结论
        note['status'] = 'not_python'
        note['enclosing'] = None
        note['non_python'] = _raw_excerpt(root_path / rel, line, radius=excerpt_lines)
        note['limits'] = [
            'source_index 只索引 .py：本文件不在索引范围内，调用方一律没查',
            '窗口只证明「这一行长这样」，不证明它的上游是谁',
        ]
        note['text'] = ('%s:%s 不是 Python，索引器不收 —— 只能给窗口，调用方得另找路'
                        '（JS 走 window 档查询或人工；接 JS 索引器是另一件事）' % (rel, line))
        return note

    idx = SourceIndex(root_path, budget or SearchBudget(), focus_files=focus_files)
    note['coverage'] = {
        'index_version': getattr(idx, 'source_sha256', '') and 'python-index-v1' or '',
        'source_sha256': getattr(idx, 'source_sha256', ''),
        'files_indexed': idx.usage.get('files', 0),
        'bytes_indexed': idx.usage.get('bytes', 0),
        'nodes': idx.usage.get('nodes', 0),
        'complete': bool(idx.complete),
        'issues': _jsonable(idx.issues),
        'seconds': round(time.monotonic() - started, 2),
    }
    if not idx.complete:
        note['limits'].append('索引不完整（见 coverage.issues）：下面的调用方只是已索引部分的，不等于全仓')

    enc = idx.enclosing(rel.replace('\\', '/'), int(line or 0))
    if not enc:
        note['status'] = 'enclosing_not_found'
        note['text'] = '在 %s 里找不到包住第 %s 行的 Python 函数——可能是模块级代码，或该文件没被索引' % (rel, line)
        return note

    node = enc.get('node')
    decorators = []
    is_async = False
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        decorators = [expression(d) for d in node.decorator_list]
        is_async = isinstance(node, ast.AsyncFunctionDef)

    note['enclosing'] = {
        'id': enc['id'], 'file': enc['file'], 'qual': enc['qual'], 'kind': enc['kind'],
        'line': enc['line'], 'end_line': enc['end_line'],
        'span_lines': enc['end_line'] - enc['line'] + 1,
        'decorators': decorators,
        'is_async': is_async,
        'nested': bool(enc['qual'].count('.') and not enc.get('class')),
        'excerpt': _excerpt(idx, enc['file'], enc['line'], min(enc['line'] + excerpt_lines - 1, enc['end_line']), excerpt_lines),
    }

    try:
        callers = idx.callers(enc['id'])
    except KeyError:
        callers = []
        note['limits'].append('callers() 需要完整符号 id；本次传的是 %s，解析失败' % enc['id'])

    counts = {}
    for call in callers:
        res = call.get('resolution') or 'unknown'
        counts[res] = counts.get(res, 0) + 1
        tier = _tier(res)
        row = {
            'resolution': res,
            'file': call['file'],
            'line': call['node'].lineno,
            'scope': call.get('scope', ''),
            'call_expression': None,
            'arguments': [],
            'bindings': [],
            'binding_complete': None,
            'excerpt': None,
        }
        if tier in ('strong', 'medium'):
            try:
                described = idx.describe_call(call, enc)
            except Exception as exc:
                described = {'error': '%s: %s' % (type(exc).__name__, exc)}
            if 'error' not in described:
                row['call_expression'] = described.get('expression')
                row['arguments'] = described.get('arguments', [])
                row['bindings'] = described.get('bindings', [])
                row['binding_complete'] = described.get('binding_complete')
                row['binding_scope'] = described.get('binding_scope', '')
            else:
                row['describe_error'] = described['error']
            row['excerpt'] = _excerpt(idx, call['file'], call['node'].lineno, call['node'].end_lineno, excerpt_lines)
            note['callers'][tier + '_calls'].append(row)
        else:
            row.pop('arguments', None)
            row.pop('bindings', None)
            row.pop('binding_complete', None)
            note['callers']['weak_calls'].append(row)

    # 可信调用方为 0 时补一遍按名扫描（基类方法被子类调用会被 callers() 静默丢掉）
    strong_n = sum(1 for c in callers if _tier(c.get('resolution') or 'unknown') == 'strong')
    note['fallback'] = {'used': False, 'matches': 0, 'why': ''}
    if strong_n == 0 and enc['name']:
        extra = _fallback_name_scan(idx, enc, callers, excerpt_lines=excerpt_lines, max_items=max_weak)
        for row in extra:
            res = row['resolution']
            counts[res] = counts.get(res, 0) + 1
            note['callers'][_tier(res) + '_calls'].append(row)
        note['fallback'] = {
            'used': bool(extra),
            'matches': len(extra),
            'why': ('callers() 只收「解析到 id」的调用；基类方法被子类用 self.x() 调时 '
                    'resolve() 返回 ([], class_member_candidate)，id 为空但标签不是 unresolved，'
                    '于是被静默丢掉。这里按叶子名补扫，标签照抄 resolve()，行标 via=fallback_name_scan。'),
        }
        if extra:
            note['limits'].append('strong=0，已按名补扫出 %d 处（via=fallback_name_scan）：'
                                  '它们证明「有人这样调」，但不证明调到的就是这个定义' % len(extra))

    note['callers']['by_resolution'] = counts
    note['callers']['total'] = len(callers) + note['fallback']['matches']
    for tier in ('strong', 'medium', 'weak'):
        note['callers'][tier] = len(note['callers'][tier + '_calls'])
    note['callers']['weak_calls'] = note['callers']['weak_calls'][:max_weak]
    note['callers']['weak_omitted'] = max(0, note['callers']['weak'] - len(note['callers']['weak_calls']))

    # 窗口内还依赖了什么：sink 那一行往上找赋值与条件，只证明语法依赖
    try:
        windows, omitted = idx.local_dependencies(enc, anchor=int(line or 0), focused=True)
    except Exception as exc:
        windows, omitted = [], 0
        note['limits'].append('local_dependencies 抛错：%s: %s' % (type(exc).__name__, exc))
    for w in windows[:6]:
        block = _excerpt(idx, w['file'], w['lo'], w['hi'], excerpt_lines)
        note['local_inputs'].append({
            'file': w['file'], 'lo': w['lo'], 'hi': w['hi'],
            'reason': w.get('reason', ''), 'excerpt': block,
        })
    note['local_inputs_omitted'] = omitted

    if note['callers']['strong'] == 0:
        note['limits'].append('没有一处可信调用方（strong=0）：这条要么没被仓库内调用（公开 API / 死代码），'
                              '要么调用发生在动态派发里 —— 两种情况都得人来定，工具不分')
    if note['callers']['weak'] > 0:
        note['limits'].append('weak 档 %d 处是同名猜测，未采信（多数是 call/forward 这类通用名）'
                              % note['callers']['weak'])

    note['text'] = render_text(note)
    return note


def render_text(note):
    """一句话说清「看了什么、看到哪一层、哪一层没看到」。"""
    if note['status'] != 'ok':
        return note.get('text') or note['status']
    enc = note['enclosing']
    c = note['callers']
    head = '候选 %s:%s 包在 %s（%s:%d-%d）' % (
        note['target']['file'], note['target']['line'], enc['qual'], enc['file'], enc['line'], enc['end_line'])
    if enc.get('decorators'):
        head += '；带装饰器 %s' % '、'.join(enc['decorators'][:3])
    if c['total'] == 0:
        who = '仓库内找不到调用方'
    else:
        parts = []
        if c['strong']:
            parts.append('可信 %d' % c['strong'])
        if c['medium']:
            parts.append('待核 %d' % c['medium'])
        if c['weak']:
            parts.append('同名猜测 %d（未采信）' % c['weak'])
        who = '调用方 %d 处：%s' % (c['total'], ' / '.join(parts))
    if note.get('fallback', {}).get('used'):
        who += '（含按名补扫 %d 处）' % note['fallback']['matches']
    best = ''
    pool = c['strong_calls'] or c['medium_calls']
    if pool:
        row = pool[0]
        params = ', '.join('%s←%s' % (b.get('parameter'), b.get('expression')) for b in (row.get('bindings') or [])[:4])
        complete = '绑定完整' if row.get('binding_complete') else '绑定不完整'
        best = '；最可信一处 %s@%s:%d（%s%s）' % (
            row.get('scope') or '?', row['file'], row['line'], complete, ('：' + params) if params else '')
    elif enc.get('decorators'):
        best = '；装饰器说明它由框架回调，不是仓库内直接调用 —— 入口形态要按装饰器判'
    elif c['total'] == 0:
        best = '；仓库内无人调用，可能是公开 API、死代码或动态派发，工具分不出来'
    cov = note['coverage']
    tail = '；索引 %s 文件 %.2fs%s' % (cov.get('files_indexed'), cov.get('seconds'), '' if cov.get('complete') else '（不完整）')
    return head + '；' + who + best + tail


def main(argv=None):
    ap = argparse.ArgumentParser(description='给一条候选生成 trace_note（语法级，不追运行时）')
    ap.add_argument('--root', help='源码根目录')
    ap.add_argument('--file', help='相对源码根的路径')
    ap.add_argument('--line', type=int, help='候选所在行')
    ap.add_argument('--jsonl', help='契约候选 jsonl（配合 --id）')
    ap.add_argument('--id', help='candidate_id')
    ap.add_argument('--out', help='写 JSON 到文件')
    ap.add_argument('--max-seconds', type=float, default=20.0)
    ap.add_argument('--max-nodes', type=int, default=3_000_000,
                    help='AST 节点预算；默认给到 300 万，OSWorld 这种量级才刚够（50 万会在半路截断）')
    ap.add_argument('--max-files', type=int, default=2000)
    ap.add_argument('--excerpt', type=int, default=8, help='每段源码窗口行数')
    ap.add_argument('--job', default='', help='串行任务名，会记进 note（便于对账）')
    args = ap.parse_args(argv)

    if args.jsonl:
        if not args.id:
            ap.error('--jsonl 要给 --id')
        rec = None
        for row in Path(args.jsonl).read_text(encoding='utf-8').splitlines():
            if not row.strip():
                continue
            obj = json.loads(row)
            if obj.get('candidate_id') == args.id:
                rec = obj
                break
        if rec is None:
            ap.error('jsonl 里没有这个 candidate_id：%s' % args.id)
        rel = args.file or rec.get('file')
        line = args.line or rec.get('line')
        root = args.root or rec.get('src_root') or ''
    else:
        rel, line, root = args.file, args.line, args.root

    if not (root and rel and line):
        ap.error('要么给 --root/--file/--line，要么给 --jsonl/--id')

    budget = SearchBudget(max_seconds=args.max_seconds, max_nodes=args.max_nodes, max_files=args.max_files)
    note = build_note(root, rel, line, budget=budget, excerpt_lines=args.excerpt)
    if args.job:
        note['job'] = args.job
    blob = json.dumps(note, ensure_ascii=False, indent=1, default=str)
    if args.out:
        Path(args.out).write_text(blob + '\n', encoding='utf-8')
    print(note['text'])
    if not args.out:
        print(blob)
    return 0 if note['status'] == 'ok' else 1


if __name__ == '__main__':
    sys.exit(main())
