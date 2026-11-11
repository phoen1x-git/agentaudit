import python
import util.util

class Source extends PyFunctionObject {
  int depth;
  CallNode callee;

  Source() {
    depth = [1..10] and
    r_calls(this, callee, depth) and
    is_sink(callee) and
    isIncludeLocation2(this.getFunction().getLocation())
  }

  int getDepth() { result = depth }
  CallNode getCallee() { result = callee }
  // deprecated
  FunctionObject getSink() { result = callee }

  FunctionObject getAMid() {
    exists(FunctionObject mid, int k | find_mid(this, callee, mid, depth, k) | result = mid)
  }


  int getMidDepth(FunctionObject mid) {
    exists(int k | find_mid(this, callee, mid, depth, k) | result = k)
  }

  /** 整个调用链 → JSON。guards / constraints 由调用方拼，没有就传 "[]"。 */
  bindingset[rule, guards, constraints]
  string getJson(string rule, string guards, string constraints) {
    result = "{\"rule\":" + jsonStr(rule) +
      ",\"depth\":" + depth.toString() +
      ",\"hops\":[" +
      concat(FunctionObject mid, int k |
        find_mid(this, callee, mid, depth, k) |
        locJson(mid.getQualifiedName(), mid.getFunction().getLocation()), "," order by k) +
      "],\"sink\":" + locJson(sinkName(callee), callee.getLocation()) +
      ",\"guards\":" + guards +
      ",\"constraints\":" + constraints + "}"
  }

  CallNode getACallNode(FunctionObject mid, FunctionObject next) {
    exists(CallNode cn |
        this.getAMid() = mid and
        this.getAMid() = next and
        (
          calls_cn(mid, next, cn)
          or
          exists(FunctionInvocation fi | calls_fi(mid, next, fi) | fi.getCall() = cn)
        )
      |
        result = cn
    )
  }

  FunctionObject getAPrev(FunctionObject fo) {
    exists(FunctionObject mid | this.getAMid() = mid and calls(mid, fo) | result = mid)
  }
}



 predicate calls(FunctionObject caller, FunctionObject callee) {
   caller != callee and
   (
     exists(FunctionInvocation fi | fi.getCaller().getFunction() = caller |
       fi.getFunction() = callee
     )
     or
     method_calls(caller, callee, _)
     or
     direct_calls(caller, callee, _)
     or
     module_calls(caller, callee, _)
     or 
     add_calls(caller, callee, _)
   )
 }
 
 predicate call_node(FunctionObject caller, CallNode cn) {
  isIncludeLocation2(caller.getFunction().getLocation()) and
   caller.getFunction().getBody().getAnItem().getAChildNode+().getAFlowNode() = cn and
   not exists(Function inner | caller.getFunction().getBody().getAnItem().getAChildNode+() = inner |
     inner.getBody().getAnItem().getAChildNode+().getAFlowNode() = cn
   )
 }
 predicate definition_node(Function caller, DefinitionNode dn) {
  isIncludeLocation2(caller.getLocation()) and
  caller.getBody().getAnItem().getAChildNode+().getAFlowNode() = dn and
  not exists(Function inner | caller.getBody().getAnItem().getAChildNode+() = inner |
    inner.getBody().getAnItem().getAChildNode+().getAFlowNode() = dn
  )
}
 predicate method_calls(FunctionObject caller, FunctionObject callee, CallNode cn) {
   call_node(caller, cn) and
   exists(Class c | c.getAMethod() = caller.getFunction() and c.getAMethod() = callee.getFunction()) and
   exists(AttrNode an, NameNode nn |
     cn.getAChild() = an and an.getAChild() = nn and nn.getId() = "self"
   |
     an.getName() = callee.getName()
   )
 }
 
 predicate direct_calls(FunctionObject caller, FunctionObject callee, CallNode cn) {
  (call_node(caller, cn) and
  (callee.isBuiltin() or caller.getFunction().getEnclosingScope() = callee.getFunction().getEnclosingScope()) and
  exists(NameNode nn | cn.getAChild() = nn | nn.getId() = callee.getName())
  )
}
predicate add_calls(FunctionObject caller, FunctionObject callee, CallNode cn) {
  (call_node(caller, cn) and
  callee.getName() = "_sys_execute" and
  cn.getFunction().(AttrNode).getNode().getName() = "Process" and
  cn.getArgByName("target").(NameNode).getId() = callee.getName()
  )
}

 predicate module_calls(FunctionObject caller, FunctionObject callee, CallNode cn) {
   call_node(caller, cn) and
   exists(Class c |
     c.getAMethod() = caller.getFunction() and
     c.getEnclosingModule() = callee.getFunction().getEnclosingModule()
   ) and
   exists(NameNode nn | cn.getAChild() = nn | nn.getId() = callee.getName())
 }
 
 predicate r_calls(FunctionObject caller, CallNode callee, int depth) {
  depth = 1 and call_node(caller, callee)
  or
  depth = getDepthLimit() and
  exists(FunctionObject mid | calls(caller, mid) | r_calls(mid, callee, depth - 1))
 }


 predicate r_functionobject_calls(FunctionObject caller, FunctionObject callee, int depth) {
  depth = 1 and calls(caller, callee)
  or
  depth = getDepthLimit() and
  exists(FunctionObject mid | calls(caller, mid) | r_functionobject_calls(mid, callee, depth - 1))
 }


 bindingset[depth]
 predicate find_mid(FunctionObject caller, CallNode callee, FunctionObject mid, int depth, int k) {
   depth >= 1 and ( k = 0 and mid = caller) or (
     k > 0 and k < depth and r_functionobject_calls(caller, mid, k) and r_calls(mid, callee, depth-k)
   ) 
 }
 // ======== 输出的 JSON 组装 ========
//
// 以前把调用链拼成 depth#name@file->...->sink@loc$$行:列$$行:列，Python 侧按
// `->` / `@` / `$$` / `#` 四层分隔符切回来。那套编码是为"跨进程传一个字符串"设计的，
// 现在两边在同一台机器上跑，直接出 JSON 更省事，也不用担心函数名里恰好含分隔符。
//
// ★ 反斜杠必须转义：Windows 的绝对路径满屏 `\`，不转义 Python 侧 json.loads 直接报错。

/** 一个字符串 → JSON 字符串字面量。 */
bindingset[s]
string jsonStr(string s) {
  result = "\"" +
    s.replaceAll("\\", "\\\\")
     .replaceAll("\"", "\\\"")
     .replaceAll("\n", " ") + "\""
}

/** 一个位置 + 它所在函数名 → JSON 对象。 */
bindingset[fn]
string locJson(string fn, Location loc) {
  result = "{\"function\":" + jsonStr(fn) +
    ",\"file\":" + jsonStr(loc.getFile().getAbsolutePath()) +
    ",\"line\":" + loc.getStartLine().toString() +
    ",\"col\":" + loc.getStartColumn().toString() +
    ",\"end_line\":" + loc.getEndLine().toString() +
    ",\"end_col\":" + loc.getEndColumn().toString() + "}"
}

/** sink 的书写形式：`obj.name` 优先，其次 `name`，最后退回整个表达式。 */
string sinkName(CallNode cn) {
  exists(AttrNode a | a = cn.getFunction() |
    if exists(a.getObject())
    then result = a.getObject().getNode().toString() + "." + a.getName()
    else result = a.getName()
  )
  or
  not cn.getFunction() instanceof AttrNode and
  result = cn.getFunction().getNode().toString()
}

string print_function(CallNode cn) {
  exists(AttrNode fan | first_attrnode(cn.getFunction(), fan) |
    result =
      fan.getObject().(NameNode).getId() + "." +
        concat(AttrNode an |
          an = cn.getFunction().getAChild*()
        |
          an.getName(), "." order by an.getLocation().getEndColumn()
        )
  )
}

predicate first_attrnode(ControlFlowNode cfn, AttrNode an) {
  an = cfn.getAChild*() and
  an.getLocation().getEndColumn() =
    rank[1](int i, AttrNode x | x = cfn.getAChild*() and i = x.getLocation().getEndColumn() | i)
}

 predicate calls_cn(FunctionObject caller, FunctionObject callee, CallNode cn) {
  caller != callee and
  (
    method_calls(caller, callee, cn)
    or
    direct_calls(caller, callee, cn)
    or
    module_calls(caller, callee, cn)
    or
    add_calls(caller, callee, cn)
  )
 }

 predicate calls_fi(FunctionObject caller, FunctionObject callee, FunctionInvocation fi) {
  caller != callee and
  (fi.getCaller().getFunction() = caller and fi.getFunction() = callee)
}

// ======== sink 判定 ========
//
// 这里原来是一段 143 行、19 个 or 分支的布尔链，每一类 sink 各写一段 if。
// 现在分三层：形状表（只看被调名字）+ 对象来源（要看对象怎么来的）+ 生成的配置项。
//
// 为什么不能压成「模块名 + 方法名」两列：其中 9 类要看**这个对象是从哪来的**。
// `run` 只有对象绑定到 ShellTool / PythonREPL 才算 sink，`execute` 只有对象名以
// `.cursor` 结尾才算。少了这一维，任意 `client.request(...)` 都会被当成 sink，
// 候选集会整片爆掉。所以「形状」和「来源」必须分开两层。

/** 被调形状：函数调用给 ("", 函数名)，方法调用给 (接收者, 方法名)。 */
private predicate calleeShape(CallNode cn, string obj, string name) {
  exists(AttrNode a | a = cn.getFunction() |
    obj = a.getObject().getNode().toString() and
    name = a.getName()
  )
  or
  exists(NameNode n | n = cn.getFunction() |
    obj = "" and
    name = n.getNode().toString()
  )
}

/** `subprocess.run` 被 submit 转手：参数里第一个就是那个 run。 */
private predicate submitRunsSubprocess(CallNode cn) {
  cn.getFunction().(AttrNode).getNode().getName() = "submit" and
  cn.getArg(0).(AttrNode).getNode().getName() = "run" and
  cn.getArg(0).(AttrNode).getNode().getObject().toString() = "subprocess"
}

/** 第一层：只看被调的名字，不管对象是哪来的。 */
private predicate sinkByShape(CallNode cn) {
  exists(string obj, string name | calleeShape(cn, obj, name) |
    (obj = "" and name in ["eval", "exec", "GitLoader"])
    or
    name = "execute_code"
    or
    (obj = "subprocess" and name in ["run", "Popen"])
    or
    (obj = "os" and name = "system")
    or
    (obj = "requests" and name in ["get", "post", "request"])
    or
    (name = "submit" and submitRunsSubprocess(cn))
  )
  or
  print_function(cn).matches("%session.execute")
  or
  print_function(cn) = "connection.execute"
  or
  print_function(cn) = "jinja.from_string"
}

/** 接收者名（`a.b.run()` 里的 `a.b`）。 */
private string receiver(CallNode cn) {
  result = cn.getFunction().(AttrNode).getObject().getNode().toString()
}

/** 接收者在 with 里面被某个构造器造出来。 */
private predicate boundInWith(CallNode cn, string ctor) {
  exists(With wi, CallNode made, NameNode nn |
    wi.getScope() = cn.getScope() and
    nn = wi.getAChildNode().getAFlowNode() and
    made = wi.getAChildNode().getAFlowNode() |
    nn.getId() = receiver(cn) and
    made.getFunction().(AttrNode).getNode().getName() = ctor
  )
}

/** 接收者在赋值语句里由某个构造器产生（只看本函数）。 */
private predicate boundByAssign(CallNode cn, string ctor) {
  exists(DefinitionNode dn |
    definition_node(cn.getFunction().(AttrNode).getNode().getScope().(Function), dn) |
    dn.getNode().toString() = receiver(cn) and
    dn.getValue().(CallNode).getFunction().(AttrNode).getNode().getName() = ctor
  )
}

/** 同 `boundByAssign`，但沿作用域向上找（嵌套定义的情况）。 */
private predicate boundByAssignUpward(CallNode cn, string ctor) {
  exists(DefinitionNode dn |
    definition_node(cn.getFunction().(AttrNode).getNode().getScope*().(Function), dn) |
    dn.getNode().toString() = receiver(cn) and
    dn.getValue().(CallNode).getNode().getFunc().toString() = ctor
  )
}

/** HTTP 会话：`session.get(...)` / `client.request(...)`，对象来自 Session 一族。 */
private predicate clientSessionBound(CallNode cn) {
  cn.getFunction().(AttrNode).getNode().getName() in ["request", "get"] and
  (
    boundInWith(cn, ["AsyncClient", "ClientSession", "Session"])
    or
    boundByAssign(cn, ["AsyncClient", "ClientSession", "Session"])
  )
}

/** 爬虫：`crawler.arun(...)`，对象来自 AsyncWebCrawler（with 或赋值）。 */
private predicate asyncWebCrawlerBound(CallNode cn) {
  cn.getFunction().(AttrNode).getNode().getName() = "arun" and
  (
    exists(With wi, CallNode made, NameNode nn |
      wi.getScope() = cn.getScope() and
      nn = wi.getAChildNode().getAFlowNode() and
      made = wi.getAChildNode().getAFlowNode() |
      nn.getId() = receiver(cn) and
      made.getFunction().getNode().toString() = "AsyncWebCrawler"
    )
    or
    exists(DefinitionNode dn |
      definition_node(cn.getFunction().(AttrNode).getNode().getScope().(Function), dn) |
      dn.getNode().toString() = receiver(cn) and
      dn.getValue().(CallNode).getFunction().getNode().toString() = "AsyncWebCrawler"
    )
  )
}

/** 工具执行器：`tool.run(...)`，对象来自 ShellTool。 */
private predicate shellToolBound(CallNode cn) {
  cn.getFunction().(AttrNode).getNode().getName() = "run" and
  exists(DefinitionNode dn |
    definition_node(cn.getFunction().(AttrNode).getNode().getScope().(Function), dn) |
    dn.getNode().toString() = receiver(cn) and
    dn.getValue().(CallNode).getNode().getFunc().toString() = "ShellTool"
  )
}

/** 交互式解释器：`repl.run(...)`，对象来自 PythonREPL（嵌套定义也认）。 */
private predicate pythonReplBound(CallNode cn) {
  cn.getFunction().(AttrNode).getNode().getName() = "run" and
  boundByAssignUpward(cn, "PythonREPL")
}

/** 笔记本单元格：`shell.run_cell(...)`，对象来自 get_ipython。 */
private predicate ipythonBound(CallNode cn) {
  cn.getFunction().(AttrNode).getNode().getName() = "run_cell" and
  boundByAssign(cn, "get_ipython")
}

/** 文本加载器：`loader.load(...)`，对象来自 AsyncHtmlLoader / WebBaseLoader。 */
private predicate htmlLoaderBound(CallNode cn) {
  cn.getFunction().(AttrNode).getNode().getName() = "load" and
  (
    boundByAssignUpward(cn, "AsyncHtmlLoader")
    or
    boundByAssignUpward(cn, "WebBaseLoader")
  )
}

/** 数据库链：`chain.run(...)` / `chain.invoke(...)`，对象由 `from_llm` 造出来。 */
private predicate sqlChainBound(CallNode cn) {
  cn.getFunction().(AttrNode).getNode().getName() in ["run", "invoke"] and
  exists(DefinitionNode dn |
    definition_node(cn.getFunction().(AttrNode).getNode().getScope().(Function), dn) |
    dn.getNode().toString() = receiver(cn) and
    dn.getValue().(CallNode).getFunction().(AttrNode).getNode().getName() = "from_llm" and
    dn.getValue().(CallNode).getFunction().(AttrNode).getObject().getNode().toString()
      in ["SQLDatabaseChain", "SQLDatabaseSequentialChain"]
  )
}

/** 光标：对象名以 `.cursor` 结尾的那次 execute。 */
private predicate cursorBound(CallNode cn) {
  cn.getFunction().(AttrNode).getNode().getName() = "execute" and
  exists(DefinitionNode dn |
    definition_node(cn.getFunction().(AttrNode).getNode().getScope().(Function), dn) |
    dn.getNode().toString() = receiver(cn) and
    print_function(dn.getValue().(CallNode)).matches("%.cursor")
  )
}

/** `client.request(...)` 的 client 是个参数，注解写了 httpx 的客户端类型。 */
private predicate httpxParamClient(CallNode cn) {
  exists(ParameterDefinition pd, AttrNode an |
    pd.getScope() = cn.getScope() and
    pd.getAnnotation() = an |
    cn.getFunction().(AttrNode).getNode().getName() = "request" and
    pd.getName() = receiver(cn) and
    an.getNode().getName().matches("%Client") and
    an.getObject().getNode().toString() = "httpx"
  )
}

/** 第二层：名字对了还不够，得看对象是从哪来的。 */
private predicate sinkByBoundObject(CallNode cn) {
  clientSessionBound(cn)
  or
  asyncWebCrawlerBound(cn)
  or
  shellToolBound(cn)
  or
  pythonReplBound(cn)
  or
  ipythonBound(cn)
  or
  htmlLoaderBound(cn)
  or
  sqlChainBound(cn)
  or
  cursorBound(cn)
  or
  httpxParamClient(cn)
}

// ======== 以下由 core/gen_ql.py 生成，不要手改 ========
// 来源：core/config/sinks.yml 里 source=extra 的 1 条
predicate is_sink_config(CallNode cn) {
  (cn.getFunction().(AttrNode).getNode().getName() = "query" and
  (
   cn.getFunction().(AttrNode).getObject().getNode().toString().regexpMatch(".*conn")
   or
   cn.getFunction().(AttrNode).getObject().(AttrNode).getNode().getName().regexpMatch(".*conn")
  ))
}

predicate is_sink(CallNode cn) {
  sinkByShape(cn) or sinkByBoundObject(cn) or is_sink_config(cn)
}
