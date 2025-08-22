import math
import string

PRINTABLE = set(string.printable)  # ASCII 0–127 minus most controls

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    from collections import Counter
    counts = Counter(data)
    n = len(data)
    return -sum((c/n) * math.log2(c/n) for c in counts.values())

def score_plaintext(candidate: bytes):
    """
    Returns (score: float in [0,1], details: dict, is_text: bool)
    Heuristics target human-readable UTF-8/plain ASCII text.
    """
    details = {}
    n = len(candidate)
    details["length"] = n
    if n == 0:
        return 0.0, {"length": 0}, False

    # 1) Encoding sanity
    try:
        s = candidate.decode("utf-8")
        details["utf8_ok"] = True
    except UnicodeDecodeError:
        # fall back to latin-1 to still compute ratios, but penalize heavily
        s = candidate.decode("latin-1", errors="ignore")
        details["utf8_ok"] = False

    # 2) Byte-level stats
    null_ratio = candidate.count(0) / n
    ctrl_bytes = sum(1 for b in candidate if b < 0x20 and b not in (0x09, 0x0A, 0x0D))
    ctrl_ratio = ctrl_bytes / n
    entropy = shannon_entropy(candidate)

    # 3) Character-level stats (on decoded string `s`)
    if not s:
        return 0.0, {"length": n, "utf8_ok": details.get("utf8_ok", False)}, False

    printable_ratio = sum(ch in PRINTABLE for ch in s) / len(s)

    # Whitespace & line structure
    ws_ratio = sum(ch.isspace() for ch in s) / len(s)
    has_newline = ("\n" in s) or ("\r" in s)

    # Token structure (simple "does it look like words?" signal)
    tokens = [t for t in s.split() if t]
    avg_tok_len = (sum(map(len, tokens)) / len(tokens)) if tokens else 0.0
    alpha_ratio = sum(ch.isalpha() for ch in s) / len(s)
    digit_ratio = sum(ch.isdigit() for ch in s) / len(s)
    punct_ratio = sum(ch in ".,;:!?()-'\"[]{}" for ch in s) / len(s)

    details.update(
        null_ratio=null_ratio,
        ctrl_ratio=ctrl_ratio,
        entropy_bits_per_byte=entropy,
        printable_ratio=printable_ratio,
        whitespace_ratio=ws_ratio,
        has_newline=has_newline,
        avg_token_len=avg_tok_len,
        alpha_ratio=alpha_ratio,
        digit_ratio=digit_ratio,
        punct_ratio=punct_ratio,
    )

    # 4) Scoring (weights are tunable)
    # Target ranges:
    # - utf8_ok True
    # - printable_ratio ~0.85–1.0
    # - entropy ~3.5–6.0 for human text (bytes); >7 often looks random/compressed
    # - low null/ctrl ratios
    # - some whitespace and occasional punctuation
    # - average token length ~3–8
    def clamp01(x): return max(0.0, min(1.0, x))

    w = {
        "utf8": 0.25,
        "printable": 0.25,
        "entropy": 0.20,
        "controls": 0.10,
        "structure": 0.20,
    }

    s_utf8 = 1.0 if details["utf8_ok"] else 0.0
    s_printable = clamp01((printable_ratio - 0.75) / (1.0 - 0.75))  # 0 at 0.75, 1 at 1.0

    # Entropy bell: score 1 near 5.0, tapering toward 0 outside [3.0, 6.8]
    center, width = 5.0, 1.2
    s_entropy = math.exp(-((entropy - center) ** 2) / (2 * width * width))
    s_entropy = clamp01(s_entropy)

    # Penalize control & null bytes
    s_controls = clamp01(1.0 - (null_ratio * 10 + ctrl_ratio * 5))

    # Structural signal: has newlines OR reasonable whitespace; avg token len 3–8; some punctuation allowed
    tok_len_score = clamp01(1.0 - abs(avg_tok_len - 5.0) / 5.0)
    ws_score = clamp01((ws_ratio - 0.02) / 0.25)  # need a bit of whitespace, but not too much
    punct_score = clamp01(1.0 - abs(punct_ratio - 0.03) / 0.08)  # light punctuation
    structure_base = 0.6 * tok_len_score + 0.2 * ws_score + 0.2 * punct_score
    if has_newline:
        structure_base = max(structure_base, 0.6)
    s_structure = clamp01(structure_base)

    score = (
        w["utf8"] * s_utf8
        + w["printable"] * s_printable
        + w["entropy"] * s_entropy
        + w["controls"] * s_controls
        + w["structure"] * s_structure
    )

    # Final decision threshold (adjust as needed)
    is_text = (score >= 0.65) and (printable_ratio >= 0.80) and (null_ratio <= 0.01)

    return float(score), details, bool(is_text)