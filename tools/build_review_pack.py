"""Build an evidence packet and blank human-review templates."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.review_pack import build_review_pack, review_template  # noqa: E402
from tools.render_review_page import render as render_review_page  # noqa: E402


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("records_dir", type=Path, help="directory containing case JSON evidence records")
    parser.add_argument("--out", type=Path, required=True, help="directory for the opinion-free packet")
    parser.add_argument("--mapping-out", type=Path, required=True, help="separate private case/source mapping file")
    parser.add_argument("--seed", type=int, default=0, help="deterministic case order seed")
    args = parser.parse_args(argv)
    try:
        output = args.out.resolve()
        mapping_output = args.mapping_out.resolve()
        if args.out.exists():
            raise ValueError(f"output directory already exists; choose a fresh path: {args.out}")
        if args.mapping_out.exists():
            raise ValueError(f"private mapping already exists; choose a fresh path: {args.mapping_out}")
        if mapping_output == output or output in mapping_output.parents:
            raise ValueError("private mapping must be outside the public packet directory")
        records = [json.loads(path.read_text(encoding="utf-8"))
                   for path in sorted(args.records_dir.glob("case-*.json"))]
        packet, mapping = build_review_pack(records, seed=args.seed)
        template = review_template(packet)
        page = render_review_page(packet, template)
        args.out.mkdir(parents=True, exist_ok=False)
        args.mapping_out.parent.mkdir(parents=True, exist_ok=True)
        (args.out / "packet.json").write_text(json.dumps(packet, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (args.out / "review-template.json").write_text(json.dumps(template, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (args.out / "review.html").write_text(page, encoding="utf-8")
        args.mapping_out.write_text(json.dumps(mapping, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        readme = [
            "# Evidence review packet",
            "",
            f"Cases: {len(packet['cases'])}",
            f"Packet SHA-256: `{packet['packet_sha256']}`",
            "",
            "Open `review.html` locally to use the offline form. Progress is session-scoped in the current browser tab and can be exported/imported as JSON; no network calls are made. The JSON packet and template remain available for scripted workflows.",
            "",
            "This packet excludes historical model opinions and omits project labels from case metadata. Source excerpts use packet-local evidence IDs and aliases, but names or locations can remain visible inside source text and unknowns. This is opinion masking, not a guarantee of reviewer blindness.",
            "",
            "Fill `review-template.json` without opening the private mapping or historical opinions. Use only evidence IDs present in the matching case. Record timezone-aware `review_started_at` and `reviewed_at` timestamps, reviewer ID, rationale, and evidence IDs. Mark `historical_opinion_consulted` false only if you have not viewed those opinions before completing the review.",
            "",
            "After review, validate each reviewer submission with `python tools/validate_review_pack.py --packet PACKET --submission SUBMISSION --out VALIDATED.json`. Validation checks packet identity, required fields, timezone-aware timestamps and evidence IDs; it does not verify whether the human conclusion is correct. Merge two or more validated submissions by repeating `--validated` in `tools/merge_review_submission.py`; it reports descriptive reviewer agreement and self-reported elapsed review time. It makes no accuracy claim.",
            "",
        ]
        (args.out / "README.md").write_text("\n".join(readme), encoding="utf-8")
        print(f"wrote {len(packet['cases'])} cases to {args.out}")
        print(f"private mapping written separately to {args.mapping_out}")
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"build_review_pack: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
