"""Nothing here may carry a local path, a secret, or a private project's vocabulary.

This guards a specific mistake: a tool grown inside a private project carries that project's
own words and its author's machine paths into the public copy. It happened here before, and
it is invisible when you are the one who wrote the words.

The term list is stored as escape sequences **on purpose** -- a literal list would itself be
an occurrence of the thing this test forbids.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

SKIP_DIRS = {".git", ".workbuddy", "__pycache__", "out", "data", "_targets", "logs",
             ".pytest_cache", ".mypy_cache", ".venv", "venv", "node_modules"}
TEXT_EXT = {".py", ".yml", ".yaml", ".md", ".tsv", ".ql", ".qll", ".txt", ".json", ".toml",
            ".cfg", ".html", ".sh"}
TEXT_NAMES = {".gitignore", ".dockerignore", "Dockerfile", "LICENSE", "Makefile"}

# Internal vocabulary from the project this tool was extracted from. Escaped deliberately.
INTERNAL_TERMS = [
    "\u53e3\u5f84",                  # conventions (internal sense)
    "\u53f0\u8d26",                  # a status ledger
    "\u4e09\u5173",                  # a three-gate review procedure
    "\u4e00\u9875\u7eb8",            # a one-page brief
    "\u5224\u636e",                  # criterion / judgement rule
    "\u9009\u9776",                  # target selection (internal slang)
    "\u5907\u6599",                  # preparing a target
    "\u63aa\u8f9e\u5ba1\u9605",      # reviewing one's own wording
    "\u53ef\u62a5\u6027",            # report-worthiness
    "\u7ea2\u7ebf",                  # red line
    "\u65cb\u94ae",                  # knob (experiment switch)
    "\u4e0a\u6e38\u5355\u53f7",      # upstream ticket number
]

PATTERNS = {
    "an absolute path from someone's machine":
        re.compile(r"[A-Za-z]:[\\/]Users[\\/]|/c/Users/|/Users/[A-Za-z0-9._-]+/"),
    "a secret": re.compile(r"\bghp_[A-Za-z0-9]{20,}|\bgithub_pat_[A-Za-z0-9_]{20,}"
                           r"|\bsk-[A-Za-z0-9]{20,}|\bAKIA[0-9A-Z]{16}"
                           r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "a private project's directory convention":
        re.compile(r"_targets[/\\]a1|a1_batch|a1db|a1src|tp2x_db|pkgdb"),
    "the author's machine account": re.compile(r"\bphoenix\b"),
}


def _text_files():
    self_path = Path(__file__).resolve()
    for p in sorted(ROOT.rglob("*")):
        if not p.is_file():
            continue
        if p.resolve() == self_path:
            # This file contains the patterns it searches for, so it would always match.
            continue
        if any(part in SKIP_DIRS for part in p.relative_to(ROOT).parts):
            continue
        if p.suffix.lower() not in TEXT_EXT and p.name not in TEXT_NAMES:
            continue
        yield p


def test_there_is_something_to_check():
    files = list(_text_files())
    assert len(files) > 20, "the scanner found no files; the walk is probably wrong"


@pytest.mark.parametrize("label,pattern", sorted(PATTERNS.items()))
def test_no_machine_specific_or_secret_strings(label, pattern):
    offenders = []
    for p in _text_files():
        for i, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if pattern.search(line):
                offenders.append(f"{p.relative_to(ROOT)}:{i}  {line.strip()[:110]}")
    assert not offenders, f"found {label}:\n" + "\n".join(offenders[:20])


def test_no_internal_vocabulary():
    offenders = []
    for p in _text_files():
        body = p.read_text(encoding="utf-8", errors="replace")
        for term in INTERNAL_TERMS:
            if term in body:
                line = next((i for i, ln in enumerate(body.splitlines(), 1) if term in ln), 0)
                offenders.append(f"{p.relative_to(ROOT)}:{line}  {term!r}")
    assert not offenders, (
        "the private project's vocabulary leaked into the public copy:\n" + "\n".join(offenders))


def test_test_files_do_not_hardcode_other_people_identities():
    """A cheap guard against pasting a real target's name in as an example."""
    suspicious = re.compile(r"\b[\w-]+/[\w.-]+\b\s*(?:#\d{2,4})")
    offenders = []
    for p in _text_files():
        if p.suffix != ".py":
            continue
        for i, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if suspicious.search(line) and "sample" not in line.lower():
                offenders.append(f"{p.relative_to(ROOT)}:{i}  {line.strip()[:110]}")
    assert not offenders, ("looks like a real repository plus issue number:\n"
                           + "\n".join(offenders[:20]))
