"""Shannon entropy validation (detection Stage 3).

Prevents low-entropy placeholders (``sk-proj-xxxx...``) from raising alerts.
"""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(data: str) -> float:
    """Return the Shannon entropy of ``data`` in bits per character."""
    if not data:
        return 0.0
    length = len(data)
    entropy = 0.0
    for count in Counter(data).values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return entropy
