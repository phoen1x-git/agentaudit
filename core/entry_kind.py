"""四类入口形态的判定参数（实施计划第五步）。

只在 Python 内部做，不新增解析器 —— 用标准库 AST 读 .py、用正则读 pyproject。

★ 这一版推翻了一个开始的思路，记在这里免得下次又走一遍：
  第一版按 **import 了什么库** 判形态（import fastapi 就是 http）。实测四类里三类全判成 http，
  因为 —— `starlette` 是被 MCP SDK 间接带进来的，`aiohttp` 在 metagpt 里是当 **HTTP 客户端**用的。
  **"import 了 web 框架" ≠ "提供 web 服务"。** 判据必须看**用法**：有没有路由装饰器、
  有没有 `FastMCP(...)`、有没有 `ArgumentParser().parse_args()`。

★ 第二个修正更要紧：**形态不是仓库的属性，是候选的属性。**
  `boss-agent-cli` 的 `[project.scripts]` 里同时有 `boss`（CLI）和 `boss-mcp`（MCP）两个入口；
  metagpt 是库，但它带了一个 web 示例。问"这个仓库是什么形态"没有唯一答案，
  所以对外两个入口分开：
    probe(root)               —— 这个仓库**提供了**哪些形态（多值，给挑选目标用）
    classify(root, rel_file)  —— **这条候选所在的文件**属于哪一类（单值，给判定用）

★ 四类的差别不是标签，是**判定参数本身不一样**：

    http    —— 问"这个端口谁能连上"。参数：监听地址、路由挂没挂鉴权依赖、生产是否注册。
    cli     —— 问"这条命令谁在敲"。参数：参数从哪来（argv / 环境变量）、跑在谁的机器上。
               ★ 用户自己敲的命令行，参数就不是"外部输入"。
    mcp     —— 问"哪个模型能自主调到它"。参数：传输方式（stdio / http）、有没有人工确认。
               ★ 模型自主调用 = 可被 prompt injection 驱动。
    library —— 问"谁会 import 它"。参数：仓库内有没有调用方、是不是公开 API。

  这四问对同一段代码可以完全不同 —— 第五步的失败信号就是"四类跑出来结论一样"。
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

WEB_FRAMEWORKS = ('fastapi', 'flask', 'django', 'starlette', 'aiohttp', 'sanic', 'tornado', 'quart')
CLI_LIBS = ('argparse', 'click', 'typer', 'docopt', 'fire')
MCP_LIBS = ('mcp', 'fastmcp', 'modelcontextprotocol')

ROUTE_DECORATOR = re.compile(r'^(\w+)\.(get|post|put|delete|patch|route|websocket)$')
APP_CTOR = re.compile(r'^(FastAPI|Flask|Starlette|Sanic|Quart|Tornado)\s*$')
MCP_CTOR = re.compile(r'^(FastMCP|Server|McpServer)\s*$')
MCP_DECORATOR = re.compile(r'^(\w+)\.(tool|function)$')
CLI_DECORATOR = re.compile(r'^(click\.)?(command|group)$')
AUTH_PATTERNS = (
    r'dependencies\s*=\s*\[?\s*(?:protected|auth|require)',
    r'Depends\(\s*(?:get_current_user|require_user|verify_token|current_user)',
    r'@\w*login_required',
)
LISTEN_PATTERNS = (
    r'uvicorn\.run\([^)]*host\s*=\s*[\'"]([^\'"]+)[\'"]',
    r'\.run\([^)]*host\s*=\s*[\'"]([^\'"]+)[\'"]',
)


def _py_files(root: Path, limit: int = 4000) -> list[Path]:
    out = []
    for p in root.rglob('*.py'):
        if any(part in ('.git', '__pycache__', 'node_modules', 'venv', '.venv') for part in p.parts):
            continue
        out.append(p)
        if len(out) >= limit:
            break
    return out


def _read(p: Path) -> str:
    try:
        return p.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return ''


def _parse(p: Path) -> ast.AST | None:
    try:
        return ast.parse(_read(p))
    except (SyntaxError, ValueError):
        return None


def _dotted(node: ast.AST) -> str:
    """把 `app.get` 这种装饰器/调用还原成点分名。还原不了返回空串。"""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return (base + '.' + node.attr) if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ''


def _decorators(tree: ast.AST) -> list[str]:
    out = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for d in node.decorator_list:
                out.append(_dotted(d))
    return out


def _calls(tree: ast.AST) -> list[str]:
    return [_dotted(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)]


# ---------------------------------------------------------------- 单文件判形态


# ---------------------------------------------------------------- 非 Python 的文本级判据


def _classify_text(text: str, rel_file: str) -> dict:
    """非 Python 文件只能看文本 —— 这是扩语言时暴露的第二个缺口。

    AST 只懂 Python，`.mjs` / `.ts` 一进来 `ast.parse` 就失败，形态直接判成 unknown，
    于是 CLI 脚本会被当成"判不了"。这里退到文本级：shebang、`process.argv`、
    `createServer(`、`@modelcontextprotocol` 这些在文本里就能看出来。

    ★ 它是 **window 级**判据：只看这个文件里出现了什么，不看它被谁 import。
    """
    t = text
    if re.search(r'@modelcontextprotocol|new\s+Server\s*\(|FastMCP', t):
        return {'kind': 'mcp', 'file': rel_file, 'why': '文本级：命中 MCP SDK',
                'params': {'detected_by': 'text', 'signal': 'modelcontextprotocol'},
                'reach': '接入这个 server 的模型可以自主调用', 'exposure': 'medium',
                'who': '接入的模型（可被 prompt injection 驱动）'}
    if re.search(r'createServer\s*\(|express\s*\(\s*\)|app\.listen\s*\(|\.listen\s*\(\s*\d', t):
        return {'kind': 'http', 'file': rel_file, 'why': '文本级：命中服务端启动',
                'params': {'detected_by': 'text', 'signal': 'createServer/express/listen'},
                'reach': '路由已注册，监听地址需另行核对', 'exposure': 'unknown',
                'who': '网络上的任何人'}
    if (t.startswith('#!') and ('node' in t.split('\n', 1)[0] or 'python' in t.split('\n', 1)[0])) \
            or 'process.argv' in t or re.search(r"require\(['\"]child_process", t) \
            or re.search(r"from\s+['\"]child_process", t):
        return {'kind': 'cli', 'file': rel_file, 'why': '文本级：shebang / argv / child_process',
                'params': {'detected_by': 'text', 'has_shebang': t.startswith('#!'),
                           'uses_argv': 'process.argv' in t},
                'reach': '只有能在那台机器上敲这条命令的人（参数是执行者自己给的）',
                'exposure': 'low', 'who': '本机执行者'}
    return {'kind': 'library', 'file': rel_file, 'why': '文本级：没有入口特征',
            'params': {'detected_by': 'text'},
            'reach': '只有显式 import 这个模块的调用方（本文件不是入口）',
            'exposure': 'low', 'who': '使用这个库的开发者'}


def _classify_local(root: str | Path, rel_file: str) -> dict:
    """判**这个文件本身**属于哪类形态。不看别的文件。

    顺序是有意排的：服务端形态（http/mcp）优先于命令形态，命令形态优先于库 ——
    因为同一个文件既注册路由又提供 main 时，前者才是决定"谁能碰到"的那个。
    """
    root = Path(root)
    p = root / rel_file
    if not p.is_file():
        return {'kind': 'unknown', 'file': rel_file, 'why': '文件不存在', 'params': {},
                'reach': '判不了', 'exposure': 'unknown', 'who': '未知'}

    if p.suffix.lower() not in ('.py', '.pyw'):
        return _classify_text(_read(p), rel_file)


    tree = _parse(p)
    if tree is None:
        return {'kind': 'unknown', 'file': rel_file, 'why': '解析失败', 'params': {},
                'reach': '判不了', 'exposure': 'unknown', 'who': '未知'}

    decs = _decorators(tree)
    calls = _calls(tree)
    text = _read(p)

    # --- http：路由装饰器，或 FastAPI()/Flask() 实例化
    route_objs = [d.split('.')[0] for d in decs if ROUTE_DECORATOR.match(d)]
    ctor = [c for c in calls if APP_CTOR.match(c)]
    if route_objs or ctor:
        host = None
        for pat in LISTEN_PATTERNS:
            m = re.search(pat, text)
            if m:
                host = m.group(1)
                break
        if host is None:
            # 监听地址常在别的文件（server.py 的 __main__ 里）；这里如实标 unknown，
            # 但要给出"路由挂在哪个对象上"这个可核对的东西
            host = 'unknown'
        auth = [a for a in AUTH_PATTERNS if re.search(a, text)]
        if host in ('0.0.0.0', '::'):
            reach, exposure = '任何能连到这个端口的人（监听所有网卡）', 'high'
        elif host in ('127.0.0.1', 'localhost'):
            reach, exposure = '只有本机能连（默认只监听回环）', 'low'
        else:
            reach, exposure = ('路由已注册，但监听地址不在本文件 —— 去 __main__ 里找', 'unknown')
        return {
            'kind': 'http', 'file': rel_file, 'params': {
                'route_objects': sorted(set(route_objs)),
                'routes': len([d for d in decs if ROUTE_DECORATOR.match(d)]),
                'app_constructors': ctor,
                'auth_patterns': len(auth),
                'listen_host': host,
            },
            'reach': reach, 'exposure': exposure, 'who': '网络上的任何人',
        }

    # --- mcp：FastMCP()/Server() 实例化，或 @x.tool() 装饰器
    mcp_tools = [d for d in decs if MCP_DECORATOR.match(d)]
    mcp_ctor = [c for c in calls if MCP_CTOR.match(c)]
    if mcp_tools or mcp_ctor:
        stdio = bool(re.search(r'stdio|StdioServerTransport', text))
        http_t = bool(re.search(r'sse|streamable_http', text, re.I))
        transport = 'stdio' if stdio and not http_t else ('http/sse' if http_t else 'unknown')
        return {
            'kind': 'mcp', 'file': rel_file, 'params': {
                'tool_decorators': len(mcp_tools),
                'tool_objects': sorted({d.split('.')[0] for d in mcp_tools}),
                'constructors': mcp_ctor,
                'transport': transport,
            },
            # ★ 这一条是 mcp 与 cli 的分水岭：没人敲命令，是模型在调
            'reach': '接入这个 server 的模型可以自主调用（传输：%s）' % transport,
            'exposure': 'medium', 'who': '接入的模型（可被 prompt injection 驱动）',
        }

    # --- cli：ArgumentParser/click/typer 的实例化与调用，或 __main__ + argv
    cli_decs = [d for d in decs if CLI_DECORATOR.match(d)]
    cli_calls = [c for c in calls if re.match(
        r'^(argparse\.ArgumentParser|click\.command|typer\.Typer|fire\.Fire)$', c)]
    has_main = bool(re.search(r'if\s+__name__\s*==\s*[\'"]__main__[\'"]', text))
    uses_argv = 'sys.argv' in text
    if cli_decs or cli_calls or (has_main and uses_argv):
        return {
            'kind': 'cli', 'file': rel_file, 'params': {
                'cli_decorators': len(cli_decs),
                'cli_calls': cli_calls,
                'has_main_guard': has_main,
                'uses_sys_argv': uses_argv,
            },
            # ★ 与 http 的关键差别：参数由执行者自己给，不是远端
            'reach': '只有能在那台机器上敲这条命令的人（参数是执行者自己给的）',
            'exposure': 'low', 'who': '本机执行者',
        }

    # --- library：以上都没有
    return {
        'kind': 'library', 'file': rel_file, 'params': {
            'route_objects': [], 'mcp_tools': 0, 'cli_calls': [],
            'is_package_module': bool(re.search(r'^\s*(from|import)\s', text, re.M)),
        },
        'reach': '只有显式 import 这个模块的调用方（本文件不是入口）',
        'exposure': 'low', 'who': '使用这个库的开发者',
    }


# ---------------------------------------------------------------- 同包入口

# ★★★ 为什么要有这一段（第三件的全部理由）：
#   「形态是候选的属性」这条认识解决了一个仓库里既有 web 又有库的问题，但它有个边界 ——
#   **入口薄、实现厚**。实测一个样本：MCP 入口在 `mcp/server.py`
#   （17 个 @mcp.tool），危险调用却写在 `mcp/actions.py`、`mcp/session.py`、`mcp/work.py`。
#   按「候选所在文件」判，那几条全是 library，于是"这个项目是什么形态"这个问题
#   在候选层面被答成了"库"——**而它明明是模型能自主调用的 MCP 服务**。
#   更普遍的形状：路由在 `routes/`、实现在 `services/`；命令在 `cli.py`、逻辑在 `core/`。
#
#   所以补一层：**候选文件被谁 import 了**。被入口文件 import 的库文件，
#   它的"谁能碰到"就不是"import 它的开发者"，而是那个入口的"谁能碰到"。
#
#   ★ 但证据强弱必须分开写，不许混：
#     via="import"       强 —— 有真实的 import 语句，能指出文件与行
#     via="same_package" 弱 —— 只是同一个包目录下有入口文件，没有 import 关系
#   弱证据只能当线索。**「同包」不等于「被调用」**，这条写进返回值里，不靠读者记。

_IMPORT_INDEX: dict[str, list] = {}

# from X import a, b   ／   import a, b as c   ／   from . import x   ／   from ..pkg import y
_IMPORT_STMT = re.compile(
    r'^[ \t]*(?:from[ \t]+(\.*)([\w.]*)[ \t]+import[ \t]+([^\n#]*)|import[ \t]+([^\n#]*))', re.M)


def _own_module(rel: str) -> str:
    """文件路径 -> 模块名。`pkg/__init__.py` 的模块名是 `pkg`，不是 `pkg.__init__`。"""
    m = rel[:-3].replace('/', '.')
    if m.endswith('.__init__'):
        return m[:-len('.__init__')]
    return m


def _imports_of(text: str, own_mod: str = '', is_pkg: bool = False
                ) -> list[tuple[str, tuple[str, ...]]]:
    """把 import 语句拆成 `[(绝对模块名, (导入的名字…))]`。

    用正则而不是 AST：这里只关心「谁提过这个名字」，而且要对**语法有错的文件**也有效 ——
    靶源码里常有 Python 2 残留，`ast.parse` 一失败就整份文件看不见了。

    ★ 相对导入必须在这里就解析成绝对名：
      第一版只认绝对名，于是在那个样本上一条强证据都找不到 ——
      真实写法是 `from . import actions, plan, store`，而我的索引里只有 `.`，
      跟 `src.<pkg>.mcp.actions` 永远对不上。
      相对导入是包内互相引用的**主要写法**，不是边角情况。
    """
    out = []
    for m in _IMPORT_STMT.finditer(text):
        if m.group(4) is not None:                 # import a, b as c
            for part in m.group(4).split(','):
                nm = part.strip().split(' as ')[0].strip()
                if nm:
                    out.append((nm, (nm,)))
            continue
        dots, src, raw = m.group(1) or '', m.group(2) or '', m.group(3) or ''
        names = tuple(n.strip().split(' as ')[0].strip() for n in raw.split(',') if n.strip())
        if dots:
            # level=1 从「本模块所在包」起算；`__init__.py` 里 level=1 就是包自身
            base = own_mod if is_pkg else own_mod.rpartition('.')[0]
            for _ in range(len(dots) - 1):
                base = base.rpartition('.')[0]
            src = (base + '.' + src).strip('.') if src else base
        if src:
            out.append((src, names))
    return out


def _import_index(root: Path) -> list[tuple[str, list]]:
    """建一次，按源码根缓存。`[(相对路径, [(绝对模块名, (名字…))])]`。"""
    key = str(root.resolve())
    hit = _IMPORT_INDEX.get(key)
    if hit is not None:
        return hit
    idx = []
    for p in _py_files(root):
        rel = str(p.relative_to(root)).replace('\\', '/')
        is_pkg = rel.endswith('__init__.py')
        idx.append((rel, _imports_of(_read(p), _own_module(rel), is_pkg)))
    _IMPORT_INDEX[key] = idx
    return idx


def _imports_module(imports: list, mod: str) -> str:
    """这个文件 import 了 `mod` 吗？是就返回一句可核对的话，否则返回 ''。"""
    parent, _, leaf = mod.rpartition('.')
    for src, names in imports:
        if src == mod or src.startswith(mod + '.'):
            return 'from %s import %s' % (src, ', '.join(n for n in names if n)[:60] or '*')
        if parent and src == parent and leaf and leaf in names:
            return 'from %s import %s' % (parent, leaf)
        for nm in names:                       # import a.b 这一档把整串塞进了 names
            if nm == mod or nm.startswith(mod + '.'):
                return 'import %s' % nm
    return ''


_RANK = {'http': 3, 'mcp': 2, 'cli': 1}


def find_sibling_entry(root: str | Path, rel_file: str,
                       max_files: int = 4000) -> dict | None:
    """候选文件是库，但同仓库有入口文件把它接进去了 —— 那个入口是什么形态。

    返回 `{kind, file, via, evidence, reach, strength}`；找不到给 `None`。
    `via="import"` 是强证据（有 import 语句），`via="same_package"` 只有"同目录"这一层关系。
    """
    root = Path(root)
    rel = str(rel_file).replace('\\', '/')
    if not rel.endswith('.py'):
        return None
    mod = rel[:-3].replace('/', '.')
    if mod.endswith('.__init__'):
        mod = mod[:-len('.__init__')]
    if not mod:
        return None
    # 仓库常把包放在 src/ 下，install 之后是顶层名 —— 两种写法都要认
    alts = [mod] + [mod[len(p):] for p in ('src.', 'lib.', 'python.') if mod.startswith(p)]

    idx = _import_index(root)
    strongest = None
    if len(idx) > max_files:
        return None
    for f, imports in idx:
        if f == rel:
            continue
        ev = ''
        for alt in alts:
            ev = _imports_module(imports, alt)
            if ev:
                break
        if not ev:
            continue
        r = _classify_local(root, f)
        k = r.get('kind')
        if k not in _RANK:
            continue
        if strongest is None or _RANK[k] > _RANK[strongest['kind']]:
            strongest = {'kind': k, 'file': f, 'via': 'import', 'strength': 'strong',
                         'evidence': ev[:160], 'reach': r.get('reach', '')}

    if strongest:
        return strongest

    # 退一档：同目录下有没有入口文件。★ 这不是"被调用"，是"挨着"。
    pkg = Path(rel).parent
    if not pkg.parts:
        return None
    for f, _ in idx:
        if f == rel or Path(f).parent != pkg:
            continue
        r = _classify_local(root, f)
        if r.get('kind') in _RANK:
            return {'kind': r['kind'], 'file': f, 'via': 'same_package', 'strength': 'weak',
                    'evidence': '同目录下有 %s 入口，但没有找到 import 关系' % r['kind'],
                    'reach': r.get('reach', '')}
    return None


def classify(root: str | Path, rel_file: str) -> dict:
    """判这个文件的形态；它是库时，再往上找一层「谁把它接进去了」。

    ★ `kind` 说的永远是**这个文件本身**的形态，不改。改了就撒谎。
      同包入口写在 `sibling_entry` 里，两者一起读才是"谁能碰到这段代码"。
    """
    r = _classify_local(root, rel_file)
    if r.get('kind') == 'library':
        sib = find_sibling_entry(root, rel_file)
        if sib:
            r['sibling_entry'] = sib
    return r


# ---------------------------------------------------------------- 仓库层面


def probe(root: str | Path) -> dict:
    """这个仓库**提供了**哪些形态（多值），给挑选目标用；不做单选，因为很多仓库不止一种。"""
    root = Path(root)
    files = _py_files(root)
    counts = {'http': [], 'mcp': [], 'cli': []}
    for p in files:
        # ★ 这里用 _classify_local 而不是 classify：probe 问的是"这个仓库自己提供了哪些入口"，
        #   跑 sibling 只会让复杂度变成 O(文件数²)，而且答案不会被用到。
        r = _classify_local(root, str(p.relative_to(root)))
        k = r['kind']
        if k in counts:
            counts[k].append(str(p.relative_to(root)))

    kinds = [k for k, v in counts.items() if v]
    has_pkg = (root / 'pyproject.toml').exists() or (root / 'setup.py').exists()
    if has_pkg or not kinds:
        kinds.append('library')

    scripts = []
    pj = root / 'pyproject.toml'
    if pj.is_file():
        scripts = re.findall(r'^\s*([\w-]+)\s*=\s*"([\w.]+):(\w+)"',
                             _read(pj), re.M)

    return {
        'root': str(root), 'kinds': kinds,
        'counts': {k: len(v) for k, v in counts.items()},
        'samples': {k: v[:3] for k, v in counts.items()},
        'console_scripts': scripts,
        'py_files': len(files),
    }


def callers(root: str | Path, names: list[str]) -> dict[str, int]:
    """某个名字在仓库里被引用了几次（排除定义行）。library 形态的胜负手。"""
    root = Path(root)
    res = {}
    files = _py_files(root)
    for name in names:
        n = 0
        for p in files:
            text = _read(p)
            if name not in text:
                continue
            for m in re.finditer(r'\b%s\b' % re.escape(name), text):
                ls = text.rfind('\n', 0, m.start()) + 1
                le = text.find('\n', m.start())
                line = text[ls:le if le > 0 else len(text)].strip()
                if re.match(r'(class|def)\s+%s\b' % re.escape(name), line):
                    continue
                n += 1
        res[name] = n
    return res


def summarize(r: dict) -> str:
    return '%s（%s）→ 谁能碰到：%s' % (r['kind'], r['exposure'], r['reach'])
