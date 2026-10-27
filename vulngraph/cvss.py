"""CVSS v3.0/v3.1 base score. CVSS v4 is intentionally not misinterpreted."""
from __future__ import annotations

import math


def cvss3_base(vector: str) -> float | None:
    if not isinstance(vector, str) or not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    try:
        metrics = dict(entry.split(":", 1) for entry in vector.split("/")[1:])
        scope = metrics["S"]
        av = {"N": .85, "A": .62, "L": .55, "P": .20}[metrics["AV"]]
        ac = {"L": .77, "H": .44}[metrics["AC"]]
        pr = ({"N": .85, "L": .62, "H": .27} if scope == "U" else {"N": .85, "L": .68, "H": .50})[metrics["PR"]]
        ui = {"N": .85, "R": .62}[metrics["UI"]]
        c, i, a = ({"N": 0, "L": .22, "H": .56}[metrics[x]] for x in ("C", "I", "A"))
        isc = 1 - (1 - c) * (1 - i) * (1 - a)
        impact = 6.42 * isc if scope == "U" else 7.52 * (isc - .029) - 3.25 * (isc - .02) ** 15
        if impact <= 0:
            return 0.0
        exploit = 8.22 * av * ac * pr * ui
        score = min(10, (impact + exploit) * (1.08 if scope == "C" else 1))        # CVSS specification rounds UP to one decimal (not Python's banker's rounding).
        return min(10.0, math.ceil((score - 1e-10) * 10) / 10)
    except (KeyError, ValueError, TypeError):
        return None
