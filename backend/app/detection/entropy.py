import math
from collections import Counter


def shannon_entropy(s: str) -> float:
    """Bits of entropy per character. Real secrets (random keys/tokens) sit
    high (~4.0-6.0 for base64/hex); English words, boilerplate, and repeated
    characters sit low (~1.5-3.0). Used to separate 'looks like a hash' from
    'looks like this hex-shaped commit message word'."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def looks_random(s: str, min_entropy: float = 3.3) -> bool:
    return shannon_entropy(s) >= min_entropy


CONTEXT_KEYWORDS = (
    "key", "secret", "token", "password", "passwd", "pwd", "credential",
    "auth", "apikey", "api_key", "access_key", "private", "bearer",
)


def has_nearby_context(text: str, match_start: int, window: int = 60) -> bool:
    """True if a secret-related keyword appears within `window` chars before
    the match. Cuts false positives on bare hex/base64-looking strings that
    are just IDs, checksums of public files, etc."""
    start = max(0, match_start - window)
    around = text[start:match_start].lower()
    return any(kw in around for kw in CONTEXT_KEYWORDS)
