"""CodeQL CSV parsing, tested without CodeQL.

The CSV path had no unit tests: `run_and_parse_argsrc` and `parse_results` were only
exercised by a real CodeQL run, which most machines do not have. Two bugs lived in that
gap - Python's default 128 KiB cell limit raising `_csv.Error` on large projects, and
`os.path.isabs` disagreeing between Windows and Linux on CodeQL's `/web/server.py` paths.

Everything here is a fixed string and a pure function. No CodeQL, no target source.
"""
from __future__ import annotations

import csv
import io
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.static_frontend import (  # noqa: E402
    _is_abs_uri,
    parse_argsrc_rows,
    parse_result_rows,
)

SEG = "%s@@%s@@%s@@%s@@%s@@%s@@%s"


def seg(kind="param", i="1", arg_line="1609", arg_text="path",
        src_file="server.py", src_line="1608", src_text="path") -> str:
    return SEG % (kind, i, arg_line, arg_text, src_file, src_line, src_text)


def row(message: str, uri: str = "/web/server.py", line: str = "10") -> list[str]:
    """One CSV row: element, description, severity, message, file, start line."""
    return ["elem", "desc", "error", message, uri, line]


def rows_from(text: str) -> list[list[str]]:
    """Round-trip through the csv module, the way a real file is read."""
    return list(csv.reader(io.StringIO(text)))


# ---------------------------------------------------------------------------
# argument-source rows: one cell, several arguments
# ---------------------------------------------------------------------------
def test_two_arguments_in_one_cell():
    # CodeQL joins every select result for one location into a single cell.
    m = seg(kind="local", i="0", arg_text="static_dir") + "\n" + seg(kind="param", i="1")
    idx = parse_argsrc_rows([row(m)])
    got = idx[("web/server.py", 10)]
    assert [a["i"] for a in got] == [0, 1]
    assert [a["kind"] for a in got] == ["local", "param"]


def test_crlf_inside_a_cell():
    m = seg(i="0") + "\r\n" + seg(i="1")
    idx = parse_argsrc_rows([row(m)])
    assert [a["i"] for a in idx[("web/server.py", 10)]] == [0, 1]


def test_short_message_segment_is_skipped():
    idx = parse_argsrc_rows([row(seg() + "\nnot@@enough@@fields")])
    assert len(idx[("web/server.py", 10)]) == 1


def test_row_with_fewer_than_six_columns_is_skipped():
    assert parse_argsrc_rows([["elem", "desc", "error", seg(), "/web/server.py"]]) == {}


def test_empty_message():
    assert parse_argsrc_rows([row("")]) == {}


def test_non_numeric_index_becomes_minus_one():
    idx = parse_argsrc_rows([row(seg(i="x", arg_line="y", src_line="z"))])
    a = idx[("web/server.py", 10)][0]
    assert a["i"] == -1
    assert a["arg_line"] == 0
    assert a["src_line"] == 0


def test_two_sink_lines_two_keys():
    idx = parse_argsrc_rows([row(seg(), line="10"), row(seg(), line="42")])
    assert sorted(idx) == [("web/server.py", 10), ("web/server.py", 42)]


# ---------------------------------------------------------------------------
# path normalisation: the same CSV must parse the same on every platform
# ---------------------------------------------------------------------------
def test_leading_slash_is_stripped():
    idx = parse_argsrc_rows([row(seg(), uri="/web/server.py")])
    assert list(idx) == [("web/server.py", 10)]


def test_absolute_path_with_source_prefix():
    idx = parse_argsrc_rows([row(seg(), uri="/home/u/proj/web/server.py")],
                            prefix="/home/u/proj")
    assert list(idx) == [("web/server.py", 10)]


def test_windows_drive_path_with_source_prefix():
    idx = parse_argsrc_rows([row(seg(), uri="C:/proj/web/server.py")],
                            prefix="C:/proj")
    assert list(idx) == [("web/server.py", 10)]


@pytest.mark.parametrize("uri", [
    "/web/server.py",
    "/C:/proj/web/server.py",
    "C:/proj/web/server.py",
    "C:\\proj\\web\\server.py",
])
def test_is_abs_uri_agrees_on_both_platforms(uri):
    # os.path.isabs("/web/server.py") is True on Linux and False on Windows;
    # CodeQL emits that shape on both. The parser must not depend on the host.
    assert _is_abs_uri(uri) is True


@pytest.mark.parametrize("uri", ["web/server.py", "", "server.py"])
def test_relative_uri_is_not_absolute(uri):
    assert _is_abs_uri(uri) is False


# ---------------------------------------------------------------------------
# quoted fields and the cell-size limit
# ---------------------------------------------------------------------------
def test_field_with_comma_and_quotes_survives():
    m = seg(arg_text='a,b "c"')
    text = '"elem","desc","error","%s","/web/server.py","10"\n' % m.replace('"', '""')
    idx = parse_argsrc_rows(rows_from(text))
    assert idx[("web/server.py", 10)][0]["arg_text"] == 'a,b "c"'


def test_cell_larger_than_the_default_csv_limit():
    # 200k characters: over Python's default 131072 limit. Before the fix this raised
    # `_csv.Error: field larger than field limit`, which reads like "nothing to report".
    big = "x" * 200000
    text = '"elem","desc","error","%s","/web/server.py","10"\n' % (seg(src_text=big))
    idx = parse_argsrc_rows(rows_from(text))
    assert len(idx[("web/server.py", 10)][0]["src_text"]) == 200000


# ---------------------------------------------------------------------------
# result rows: JSON payload in the message cell
# ---------------------------------------------------------------------------
def payload(rule="py/path-injection", func="join", line=42) -> str:
    return ('{"rule":"%s","depth":2,"sink":{"function":"%s","file":"/web/server.py",'
            '"line":%d,"col":5},"hops":[{"function":"index"}],"guards":[]}'
            % (rule, func, line))


def test_two_results_in_one_cell():
    out, bad = parse_result_rows([row(payload(line=42) + "\n" + payload(line=43))], "p")
    assert bad == 0
    assert [f.sink_line for f in out] == [42, 43]
    assert out[0].sink_uri == "/web/server.py"


def test_bad_json_is_counted_not_swallowed():
    out, bad = parse_result_rows([row(payload() + "\n{not json")], "p")
    assert len(out) == 1
    assert bad == 1


def test_blank_line_in_cell_is_not_counted_as_bad():
    out, bad = parse_result_rows([row(payload() + "\n\n")], "p")
    assert len(out) == 1
    assert bad == 0


def test_result_row_with_fewer_than_five_columns_is_skipped():
    out, bad = parse_result_rows([["elem", "desc", "error", payload()]], "p")
    assert out == [] and bad == 0
