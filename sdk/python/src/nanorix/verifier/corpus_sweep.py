"""Run the published conformance corpus against the Python verifier.

The corpus is the interoperability contract. Until this existed, the Python
verifier's agreement with the reference implementation was asserted rather than
checked, and the README had to say so.

Each fixture ships a committed verdict in a `.expected.json` sibling. This
compares three things against it, under the policy the fixture itself declares:
`valid`, `stage_reached`, and the full wire-form failure object. The prose
rendering of a failure is not compared, only the structured form, because the
prose is allowed to differ between implementations and the wire form is not.

    python -m nanorix.verifier.corpus_sweep <corpus-dir>

Exit 0 = every fixture matched. Exit 1 = at least one disagreed, and every
disagreement is printed. Exit 2 = the corpus could not be read, which is
reported as a failure rather than as an empty pass.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from nanorix.verifier._verify import verify
from nanorix.verifier._ladder import VerifierPolicy


def collect_fixtures(root: Path) -> List[Path]:
    """Every fixture in the corpus, sorted, excluding verdicts and the index."""
    return sorted(
        p
        for p in root.rglob("*.json")
        if not p.name.endswith(".expected.json") and p.name != "index.json"
    )


def policy_from_expected(expected: Dict[str, Any]) -> VerifierPolicy:
    """A region or authority mismatch is only reachable under the matching pin.

    The pin travels with the fixture rather than living in this harness, so
    every implementation reads the same policy from the same place.
    """
    pins = expected.get("policy") or {}
    # The policy fields are `str` with "" meaning "accept anything", not
    # Optional — mirror that rather than passing None through.
    return VerifierPolicy(
        required_region=pins.get("required_region") or "",
        required_authority_id=pins.get("required_authority_id") or "",
    )


def compare(fixture: Path, expected: Dict[str, Any]) -> List[str]:
    result = verify(fixture, policy_from_expected(expected))
    out: List[str] = []
    if result.valid != expected["valid"]:
        out.append(f"valid: expected {expected['valid']}, got {result.valid}")
    if result.stage_reached != expected["stage_reached"]:
        out.append(
            f"stage_reached: expected {expected['stage_reached']}, got {result.stage_reached}"
        )
    want = expected.get("failure_reason")
    got = result.failure
    if json.dumps(want, sort_keys=True) != json.dumps(got, sort_keys=True):
        out.append(f"failure_reason: expected {want}, got {got}")
    return out


def sweep(root: Path) -> Tuple[int, List[str]]:
    fixtures = collect_fixtures(root)
    if not fixtures:
        return 0, [f"corpus at {root} is empty; the sweep would pass vacuously"]

    failures: List[str] = []
    for fixture in fixtures:
        rel = fixture.relative_to(root)
        sibling = fixture.with_name(fixture.stem + ".expected.json")
        if not sibling.exists():
            failures.append(f"{rel}: no .expected.json sibling")
            continue
        expected = json.loads(sibling.read_text())
        for problem in compare(fixture, expected):
            failures.append(f"{rel}: {problem}")
    return len(fixtures), failures


def main(argv: Optional[List[str]] = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    if len(args) != 1:
        print(__doc__.strip().splitlines()[-3], file=sys.stderr)
        return 2
    root = Path(args[0])
    if not root.is_dir():
        print(f"not a directory: {root}", file=sys.stderr)
        return 2

    total, failures = sweep(root)
    if failures:
        print(f"  {len(failures)} disagreement(s) across {total} fixture(s):")
        for f in failures[:40]:
            print(f"    {f}")
        if len(failures) > 40:
            print(f"    ... and {len(failures) - 40} more")
        return 1
    print(f"  {total} fixtures, all matching their committed verdicts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
