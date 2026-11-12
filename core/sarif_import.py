"""Bounded SARIF input adapter; analyzer claims remain untrusted candidate metadata."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit

from .finding import Finding, make_fingerprint

VERSION = "sarif-import-v1"
LANGUAGES = {
    ".py": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".scala": "scala", ".sc": "scala",
    ".go": "go", ".rs": "rust", ".sol": "solidity", ".swift": "swift",
    ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
    ".hh": "cpp", ".hpp": "cpp", ".hxx": "cpp", ".cs": "csharp",
    ".fs": "fsharp", ".fsi": "fsharp", ".fsx": "fsharp", ".vb": "vb",
    ".php": "php", ".rb": "ruby", ".pyi": "python", ".pl": "perl", ".pm": "perl",
    ".lua": "lua", ".r": "r", ".sql": "sql", ".sh": "bash", ".bash": "bash",
    ".zsh": "bash", ".ps1": "powershell", ".ex": "elixir", ".exs": "elixir",
    ".erl": "erlang", ".hrl": "erlang", ".hs": "haskell", ".lhs": "haskell",
    ".clj": "clojure", ".cljs": "clojure", ".cljc": "clojure", ".groovy": "groovy",
    ".yml": "yaml", ".yaml": "yaml", ".json": "json", ".toml": "toml",
    ".xml": "xml", ".html": "html", ".htm": "html", ".css": "css",
    ".scss": "scss", ".md": "markdown", ".tf": "hcl", ".hcl": "hcl",
}


def _positive(value, label):
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(label + " must be a positive integer")
    return value


def import_file(path, source_root, project, *, max_bytes=16*1024*1024, max_results=1000,
                max_source_bytes=16*1024*1024, max_file_bytes=512*1024, max_locations=64):
    for value, name in ((max_bytes, "max_bytes"), (max_results, "max_results"),
                        (max_source_bytes, "max_source_bytes"), (max_file_bytes, "max_file_bytes"),
                        (max_locations, "max_locations")):
        _positive(value, name)
    root = Path(source_root).resolve()
    if not root.is_dir():
        raise ValueError("source root is not a directory")
    with Path(path).open("rb") as stream:
        raw = stream.read(max_bytes+1)
    if len(raw) > max_bytes:
        raise ValueError("SARIF input-size budget exceeded")
    def nonfinite(value):
        raise ValueError("non-finite JSON number: " + value)
    data = json.loads(raw.decode("utf-8-sig"), parse_constant=nonfinite)
    if not isinstance(data, dict) or data.get("version") != "2.1.0" or not isinstance(data.get("runs"), list):
        raise ValueError("expected a SARIF 2.1.0 object with runs")
    input_sha = hashlib.sha256(raw).hexdigest()
    findings, issues, files, total_bytes, considered = {}, [], {}, 0, 0

    def uri_path(uri, bases, base_id="", seen=None):
        if not isinstance(uri, str) or not uri:
            raise ValueError("missing artifact URI")
        value = unquote(uri).replace("\\", "/")
        if "\x00" in value:
            raise ValueError("invalid artifact URI")
        if re.match(r"^[A-Za-z]:/", value):
            candidate = Path(value)
        else:
            parsed = urlsplit(value)
            if parsed.query or parsed.fragment or parsed.scheme not in {"", "file"} or parsed.netloc not in {"", "localhost"}:
                raise ValueError("only local source artifacts are supported")
            value = parsed.path
            if parsed.scheme == "file" and re.match(r"^/[A-Za-z]:/", value):
                value = value[1:]
            candidate = Path(value)
        if not candidate.is_absolute():
            base = root
            if base_id:
                seen = set(seen or ())
                if base_id in seen or len(seen) >= 8:
                    raise ValueError("cyclic or deep URI base")
                seen.add(base_id)
                definition = bases.get(base_id)
                if not isinstance(definition, dict):
                    raise ValueError("URI base is missing")
                base = uri_path(definition.get("uri"), bases, definition.get("uriBaseId", ""), seen)
            candidate = base / candidate
        resolved = candidate.resolve()
        resolved.relative_to(root)
        return resolved

    def source(path):
        nonlocal total_bytes
        rel = path.relative_to(root).as_posix()
        if rel not in files:
            with path.open("rb") as stream:
                content = stream.read(max_file_bytes+1)
            if len(content) > max_file_bytes or total_bytes+len(content) > max_source_bytes:
                raise ValueError("source byte budget exceeded")
            if b"\x00" in content:
                raise ValueError("source artifact contains NUL bytes")
            text = content.decode("utf-8-sig")
            total_bytes += len(content)
            files[rel] = {"sha256": hashlib.sha256(content).hexdigest(), "lines": text.splitlines()}
        return rel, files[rel]

    for run_index, run in enumerate(data["runs"]):
        if not isinstance(run, dict):
            raise ValueError("invalid SARIF run")
        driver = run.get("tool", {}).get("driver", {})
        backend = str(driver.get("name") or "external")[:128]
        bases = run.get("originalUriBaseIds", {})
        artifacts = run.get("artifacts", [])
        hashes = {}
        for artifact in artifacts:
            try:
                location = artifact.get("location", {})
                p = uri_path(location.get("uri"), bases, location.get("uriBaseId", ""))
                expected = artifact.get("hashes", {}).get("sha-256")
                if expected:
                    hashes.setdefault(p.as_posix(), set()).add(str(expected).lower())
            except (OSError, ValueError, KeyError, TypeError, AttributeError):
                continue

        def location(value, role):
            physical = value.get("physicalLocation", {})
            loc = physical.get("artifactLocation", {})
            if "index" in loc:
                index = loc["index"]
                if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < len(artifacts):
                    raise ValueError("invalid artifact index")
                loc = {**artifacts[index].get("location", {}), **loc}
            p = uri_path(loc.get("uri"), bases, loc.get("uriBaseId", ""))
            rel, file = source(p)
            region = physical.get("region", {})
            line = _positive(region.get("startLine"), "startLine")
            end = _positive(region.get("endLine", line), "endLine")
            column = _positive(region.get("startColumn", 1), "startColumn")
            if not line <= end <= len(file["lines"]):
                raise ValueError("source region is outside the current file")
            context = physical.get("contextRegion") or {}
            lo = _positive(context.get("startLine", max(1,line-8)), "context startLine")
            hi = _positive(context.get("endLine", min(len(file["lines"]),end+8)), "context endLine")
            if not 1 <= lo <= line <= end <= hi <= len(file["lines"]):
                raise ValueError("invalid context region")
            expected = hashes.get(p.as_posix(), set())
            match = "matched" if expected == {file["sha256"]} else "mismatch" if expected else "unverified"
            logical = value.get("logicalLocations") or []
            return {"file": rel, "line": line, "end_line": end, "column": column,
                    "context_start": lo, "context_end": hi, "context_declared": bool(context),
                    "sha256": file["sha256"], "hash_status": match, "expected_sha256": sorted(expected),
                    "role": role, "snippet": file["lines"][line-1],
                    "logical_name": str(logical[0].get("fullyQualifiedName") or logical[0].get("name") or "")[:512] if logical else ""}

        results = run.get("results", [])
        if not isinstance(results, list):
            raise ValueError("invalid SARIF results")
        for result_index, result in enumerate(results):
            if considered >= max_results:
                issues.append({"run": run_index, "result": result_index, "reason": "result budget exceeded",
                               "remaining_in_run": len(results)-result_index})
                break
            considered += 1
            try:
                primary = location(result["locations"][0], "primary")
                # The adapter consumes exact line locations from an existing analyzer;
                # it does not parse the source language itself. Keep recognized labels
                # for common formats and safely fence custom/extensionless text as plain text.
                language = LANGUAGES.get(Path(primary["file"]).suffix.lower(), "text")
                points = [primary]
                partial = False
                for flow_index, flow in enumerate(result.get("codeFlows", [])):
                    for thread_index, thread in enumerate(flow.get("threadFlows", [])):
                        for step_index, step in enumerate(thread.get("locations", [])):
                            if len(points) >= max_locations:
                                partial = True
                                continue
                            try:
                                point = location(step["location"], "backend_flow_candidate")
                                point.update(flow=flow_index, thread=thread_index, step=step_index)
                                points.append(point)
                            except (OSError, ValueError, KeyError, TypeError) as exc:
                                partial = True
                                issues.append({"run": run_index, "result": result_index, "reason": "flow location omitted: " + str(exc)})
                for related in result.get("relatedLocations", []):
                    if len(points) >= max_locations:
                        partial = True
                        break
                    try:
                        points.append(location(related, "related_candidate"))
                    except (OSError, ValueError, KeyError, TypeError):
                        partial = True
                rule = result.get("ruleId")
                if not rule and isinstance(result.get("ruleIndex"), int):
                    index = result["ruleIndex"]
                    if isinstance(index, bool) or not 0 <= index < len(driver.get("rules", [])):
                        raise ValueError("invalid rule index")
                    rule = driver["rules"][index]["id"]
                rule = str(rule or "unknown")[:256]
                fp = make_fingerprint(project, primary["file"], backend+"|"+rule+"|"+str(primary["line"]), primary["snippet"])
                status = ("mismatch" if any(p["hash_status"] == "mismatch" for p in points) else
                          "unverified" if partial or any(p["hash_status"] == "unverified" for p in points) else "matched_referenced_files")
                details = {"run":run_index, "result":result_index, "level":result.get("level"),
                           "message":str(result.get("message", {}).get("text") or result.get("message", {}).get("markdown") or "")[:4096],
                           "partial_fingerprints":result.get("partialFingerprints", {}),
                           "properties":result.get("properties", {})}
                if fp in findings:
                    fd = findings[fp]
                    fd.variants += 1
                    fd.analysis_provenance["backend_results"].append(details)
                    available = max_locations-len(fd.analysis_provenance["locations"])
                    fd.analysis_provenance["locations"].extend(points[:available])
                    if len(points) > available:
                        partial = True
                        status = "mismatch" if status == "mismatch" else "unverified"
                    fd.analysis_provenance["partial_context"] |= partial
                    if status == "mismatch" or fd.analysis_provenance["source_version_status"] != "mismatch" and status != "matched_referenced_files":
                        fd.analysis_provenance["source_version_status"] = status
                else:
                    fd = Finding(project=project, fingerprint=fp, language=language, rule=rule,
                                 sink_func="", sink_uri=primary["file"], sink_line=primary["line"], sink_col=primary["column"],
                                 entry=primary["logical_name"], snippet=primary["snippet"], src_root=str(root),
                                 chain=f"{len(points)-1} backend-related source positions; separate flows/threads retained in provenance",
                                 analysis_provenance={"adapter":VERSION, "backend":backend, "backend_version":driver.get("version"),
                                                      "input_sha256":input_sha, "language":language,
                                                      "source_version_status":status,
                                                      "source_version_scope":"referenced artifact hashes only; no deployment or whole-project attestation",
                                                      "locations":points, "backend_results":[details], "partial_context":partial})
                    findings[fp] = fd
            except (OSError, ValueError, KeyError, TypeError, IndexError, AttributeError, UnicodeError) as exc:
                issues.append({"run":run_index,"result":result_index,"reason":str(exc)})
    return sorted(findings.values(), key=lambda fd:(fd.sink_uri,fd.sink_line,fd.rule)), {
        "adapter":VERSION, "input_sha256":input_sha, "considered_results":considered,
        "imported_candidates":len(findings), "source_files_read":len(files), "source_bytes_read":total_bytes,
        "issues":issues, "target_code_executed":False, "llm_calls":0, "llm_cost_cny":0.0,
        "scope":"external analyzer candidate/context import; not an independent scan or vulnerability confirmation"}
