# `core/ql/js/` —— 扩语言那一档（实施计划第六步）

这里放的是 **JavaScript 侧**的 CodeQL 查询。Python 的查询在上一级 `core/ql/`，两套不混：
Python 那套的输出列和这一套完全不同，解析器也是两个（`core/static_frontend.py` 对 Python，
`tools/import_js_candidates.py` 对 JS）。

## 为什么单独一个 ql 包

`qlpack.yml` 声明的是 `codeql/javascript-all`，和 Python 那包（`codeql/python-all`）的依赖不同。
CodeQL 要求一个 pack 只依赖一种语言，所以必须分开。

```bash
# 一次性：装 JS 的查询库
codeql pack download codeql/javascript-all@3.0.0
cd core/ql/js && codeql pack install      # 生成 codeql-pack.lock.yml
```

## 三支查询各干什么

| 文件 | id | 用途 |
|---|---|---|
| `sinks2.ql` | `js-window/sink2` | **生产用这支**。window 级 + 一条不追数据的启发式：接收者名字像正则（`pattern` / `regex` / `re`）的 `exec` 不算 |
| `sinks.ql` | `js-window/sink` | 纯 window 版，不带启发式。留着对账：两版跑同一靶，差集就是启发式吃掉的那几条 |
| `probe_receiver_type.ql` | `js-window/probe-receiver-type` | 量假阳用的探针。**四版都空**（`ty.ql`~`ty4.ql` 试过），见下 |

## 这一档的真实代价（别忘）

`trace_level` 只能是 `window`，意味着**只看到 sink 那一行和接收者的名字**，不追变量定义、
不追调用链。cascadeflow 上的实测：报 **9 条，8 条是正则的 `pattern.exec()`**，
窗口内分不出 `pattern.exec` 和 `child_process.exec`。

想升 `full` 得拿到接收者类型，试过四版：

1. `CallExpr.getCalleeName()` + `getReceiver().getType().toString()` —— 空
2. `getReceiver().getType().getName()` —— 空
3. 两者拼一起 —— 空
4. 换 `MethodCallExpr.getMethodName()` —— 空

结论不是"这批调用没类型"，是**这一档拿不到类型**。所以 JS 现在停在 window，
不是没做完，是做到这里发现路走不通 —— 升档得换一个能给类型的后端（类型推断 / TS 编译产物 / JSDoc）。

## 跑法（三步，现在是两条命令 + 一步导入）

```bash
# 1. 建库（--codeql-language 就是为这个开关加的）
codeql database create <db> --language=javascript --source-root <靶>
#    或走主程序： python app/scan.py --path <靶> --codeql-language javascript

# 2. 跑查询出 CSV
codeql database analyze <db> core/ql/js/sinks2.ql --format=csv --output=js_results.csv \
    --search-path=core/ql/js

# 3. 导成契约候选（会顺手按候选所在文件判 entry.kind）
python tools/import_js_candidates.py --csv js_results.csv \
    --root <靶> --repo owner/name --rule-id js-window/sink2 --out candidates.v1.jsonl
```

下游（案卷、判定、报告）一行都不用改 —— 这是「跨语言那一层」的意义。


---

## `arg_origin.ql`（加）

**干什么**：对每个危险调用的**每个实参**，标出它是 `literal / template / varref / expr`。
输出格式是 `spawnSync|arg0:varref:command`（每行一个实参，带 sink 名）。

**为什么加**：`tools/guard_filler.py` 是 Python-only（吃 `ast`），JS 候选的 `guards_relevant`
那一栏填不了。窗口档能拿到的最有价值的信息就是「实参是字面量还是变量」——
全字面量就没必要立案。

**三个必须记住的格式细节**（都踩过）：

1. **problem 查询的 CSV 没有表头行。** 9 字段一条记录：
   `name, description, severity, message, file, start_line, start_col, end_line, end_col`。
2. **message 里的换行是真的换行**：一个 sink 三个实参就是三行。
   用 `csv.reader` 读整份文件是对的，按物理行 `splitlines()` 再拼是错的。
3. **message 每行都要带 sink 名**。不带的话 Python 侧不知道这是哪个 sink，
   就没法判「哪几个实参是危险位置」——`spawnSync(cmd, args, {options})` 的第三个参数是配置对象，
   天生是 `expr`，算进去会让每条候选都变成 `has_expr`（实测 11/11 全误标）。

**分辨率的边界**：`slice.toString()` 对长文本会省略（`{\n    c ... '],\n  }`），
所以 `template` 里有没有 `${}` 插值，Python 侧**判不准**。这类一律按"非字面量"处理，
宁可多一条待查，不许漏。
