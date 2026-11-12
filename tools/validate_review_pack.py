"""Validate human review fields and citations without grading conclusions."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.review_pack import validate_review_submissions  # noqa: E402


def main(argv=None):
    parser = argparse.ArgumentParser(prog="agentaudit review-validate", description=__doc__)
    parser.add_argument("--packet", type=Path, required=True,
                        help="the packet.json the reviewer was given")
    parser.add_argument("--submission", type=Path, required=True,
                        help="the filled review template")
    parser.add_argument("--out", type=Path, required=True,
                        help="where to write the validated submission")
    parser.add_argument("--allow-partial", action="store_true",
                        help="accept a submission that covers only some of the packet's cases")
    args = parser.parse_args(argv)
    try:
        packet = json.loads(args.packet.read_text(encoding="utf-8"))
        submission = json.loads(args.submission.read_text(encoding="utf-8"))
        validated = validate_review_submissions(packet, submission, require_all=not args.allow_partial)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(validated, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"validated {validated['review_count']} human reviews; no verdict accuracy was assessed")
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"validate_review_pack: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
