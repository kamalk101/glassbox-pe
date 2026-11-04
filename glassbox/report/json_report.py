"""JSON report rendering."""

from __future__ import annotations

import json

from ..schema import Case


def render_json(case: Case) -> str:
    return json.dumps(case.to_dict(), indent=2)
