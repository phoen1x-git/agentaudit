import python

// deprecated

 string locStr(Location loc) {
   result =
     loc.getFile().getAbsolutePath() + "#" + loc.getStartLine().toString() + ":" +
       loc.getStartColumn().toString() + "#" + loc.getEndLine().toString() + ":" +
       loc.getEndColumn().toString()
 }

 

 

 

 string getStrFuncName() {
   result = ["split", "index", "rindex"]
 }

 int getDepthLimit() {
   result = [2..20]
 }

// ======== 路径过滤（由 core/gen_ql.py 生成，不要手改）========
// ★ 修的是什么：
//   论文用 `s.matches("%test%")` 判路径（s = loc.toString()，**绝对路径**）
//   → **仓库目录名里含 "test" 就整仓被排除**。
//   实证：靶 `firetix/vibe-coding-penetration-**tester**`
//     · 修前：`[parse] 原始结果 0 条`（主查询空，而 argsrc 仍报 36 个 sink 位置）→ **假 0**
//     · 修后：`[parse] 原始结果 48 条` → 去重 11 条 → 判定层出 **vuln ×1**
//   同批 TaintP2X 里被整仓杀掉的还有 `GreyDGL/PentestGPT`（名字含 "pentest"）。
//   ★ 这是一整类：**任何取名带 pentest / tester / latest / contest 的 Agent 项目都会被静默跳过**。
// ★ 最小单变量修复：**把黑名单作用在 `getRelativePath()` 上**（去掉仓库目录名那一段），
//   其余语义（tests/ demo/ example/ 都排除）与论文**逐字一致**。

string substringBlack() { result = ["test", "miniconda", "demo", "example", "qltracer", "newrepo", "python39"] }

// ★ 兼容：论文原列表
string getBlacklist() { result = ["test", "miniconda", "demo", "example", "qltracer", "newrepo", "Python39"] }

predicate isIncludeLocation2(Location loc) {
  exists(string p | p = loc.getFile().getRelativePath().replaceAll("\\", "/").toLowerCase() |
    // ★ 关键：用**相对路径**（去掉仓库目录名）→ "…-penetration-tester" 这类仓库名不再整仓被杀
    forall(string b | b = substringBlack() | not p.matches("%" + b + "%")))
}

bindingset[s]
predicate isIncludeLocationStr(string s) {
    forall(string black | black = substringBlack() | not s.matches("%" + black + "%"))
 }

predicate isIncludeLocation(Location loc) { isIncludeLocation2(loc) }
