"""内核 · 目标健康门（扫之前先过这道门）。

★ 一句话：**归档 / 长期无人维护 / fork / 被停用 → 不扫，并且说出为什么。**

★ 这道门存在的直接原因：2026-10-09 那轮 5 条候选最后 0 条值得报，
  其中两个仓库已归档、一个被 issue 报遍。**那次不是检测错了，是目标不该扫。**

★★ 两个模式（2026-10-10 加，`docs/113` §八）：
   **「能不能报出去」≠「能不能检出」—— 用途不同，门槛就不该一样。**

   | 模式 | 用途 | 归档 / 长期不维护 | 为什么 |
   |---|---|---|---|
   | `alive`（默认） | 报给开发者 | **跳过** | 归档仓库没人修，报了也白报 |
   | `detect` | 验证检出能力 / 算命中率 | **不跳过** | 目标里**有真洞**才是关键，仓库活不活着不影响能不能检出 |

   ★ 为什么必须分开：实测把 `alive` 用在所有场景后，
     **把手里唯一有真洞的测试集换掉了** —— 老 3 个目标（2 个已归档）产出 6 条 vuln
     （含公告真阳），而"健康"的新目标批 **0 条** → **能力反而测不出来**。

★ 与 upstream.py 的分工：
    gate  —— 扫**之前**，判断"这个目标值不值得扫"（仓库级）
    upstream —— 报**之前**，判断"这一条值不值得报"（条目级）
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

from . import gh

_ROOT = Path(__file__).resolve().parent.parent
_CFG = Path(__file__).resolve().parent / "config" / "gate.yml"
_CACHE = _ROOT / "data" / "gate_cache"

MODE_ALIVE = "alive"      # 报给开发者用：仓库得还活着
MODE_DETECT = "detect"    # 验证检出能力用：只要里面有真洞，归档也行


def load_cfg() -> dict:
    with open(_CFG, "r", encoding="utf-8") as fh:
        return (yaml.safe_load(fh) or {}).get("gate", {})


def _cache_path(repo: str) -> Path:
    return _CACHE / (repo.replace("/", "__") + ".json")


def _repo_info(repo: str, tok: str, ttl_days: float) -> tuple[dict | None, bool]:
    """取仓库元信息（带 TTL 缓存）。返回 (info, from_cache)。"""
    p = _cache_path(repo)
    if p.exists():
        try:
            age_days = (time.time() - p.stat().st_mtime) / 86400.0
            if age_days < ttl_days:
                return json.loads(p.read_text(encoding="utf-8")), True
        except Exception:
            pass
    d = gh.get_json(f"{gh.API}/repos/{repo}", tok=tok)
    if d:
        _CACHE.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8")
    return d, False


def _months_since(iso: str | None) -> float | None:
    if not iso:
        return None
    try:
        t = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except Exception:
        return None
    now = datetime.now(timezone.utc)
    return round((now - t).days / 30.44, 1)


def check(repo: str, cfg: dict | None = None, tok: str | None = None,
          mode: str | None = None) -> dict:
    """检查一个仓库健不健康。返回 verdict + 具体原因。

    `mode`：`alive`（默认，报给开发者）或 `detect`（验证检出能力）。
    ★ detect 模式下**跳过"归档 / 长期不维护"这两条** —— 因为"能不能检出"跟
      仓库活不活着无关，而把有真洞的归档目标筛掉会让能力测不出来（`docs/113` §八）。
      fork / 停用 仍然检查（fork 的洞上游不认，跟用途无关）。
    """
    cfg = cfg or load_cfg()
    mode = mode or cfg.get("mode", MODE_ALIVE)
    detect = (mode == MODE_DETECT)
    out: dict = {"repo": repo, "verdict": "PASS", "reasons": [], "mode": mode}
    try:
        tok = tok or gh.token()
    except SystemExit as e:
        out["verdict"] = "UNKNOWN"
        out["reasons"].append(str(e))
        return out
    info, cached = _repo_info(repo, tok, float(cfg.get("ttl_days", 1)))
    out["cached"] = cached
    if not info:
        out["verdict"] = "UNKNOWN"
        out["reasons"].append("取不到仓库信息（网络或权限）")
        return out

    out["archived"] = bool(info.get("archived"))
    out["fork"] = bool(info.get("fork"))
    out["disabled"] = bool(info.get("disabled"))
    out["stars"] = info.get("stargazers_count")
    out["pushed_at"] = info.get("pushed_at")
    out["default_branch"] = info.get("default_branch")
    out["months_since_push"] = _months_since(info.get("pushed_at"))

    if cfg.get("skip_if_fork", True) and out["fork"]:
        out["reasons"].append("是 fork（上游不认 fork 的洞）")
    # ★★ detect 模式下**不查**归档 / 维护活跃度 —— 见函数 docstring 与 `docs/113` §八
    if not detect:
        if cfg.get("skip_if_archived", True) and out["archived"]:
            out["reasons"].append("★ 仓库已归档（不会再有修复）")
    if cfg.get("skip_if_disabled", True) and out["disabled"]:
        out["reasons"].append("仓库已被停用")
    ms = out["months_since_push"]
    stale = float(cfg.get("max_stale_months", 12))
    if not detect and ms is not None and ms > stale:
        out["reasons"].append(f"★ 已 {ms} 个月没有 push（阈值 {stale}）→ 视为无人维护")
    min_stars = int(cfg.get("min_stars", 0) or 0)
    if min_stars and (out["stars"] or 0) < min_stars:
        out["reasons"].append(f"星数 {out['stars']} < {min_stars}")

    if out["reasons"]:
        out["verdict"] = "SKIP"
    return out


def summary(res: dict) -> str:
    if res["verdict"] == "PASS":
        return (f"PASS　{res.get('stars')}★　最后 push {res.get('pushed_at','?')[:10]}"
                f"（{res.get('months_since_push')} 个月前）")
    if res["verdict"] == "UNKNOWN":
        return "UNKNOWN　" + "；".join(res["reasons"])
    return "SKIP　" + "；".join(res["reasons"])
