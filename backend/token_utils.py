"""
Token counting with tiktoken, with a conservative fallback.

We use the ``cl100k_base`` encoding as a conservative approximation for
Qwen / Gemma tokenizers.  It may slightly *over*-count, which is safe —
we would rather send a bit less data per chunk than risk exceeding the
model's context window.

If tiktoken is not yet installed in the runtime environment, a conservative
character-based heuristic (~3.3 chars per token for code/JSON) is used so
utilities and tests never crash.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

_ENCODING_NAME = "cl100k_base"
_encoder = None
_tiktoken_available = True

try:
    import tiktoken
except ImportError:
    _tiktoken_available = False


def _get_encoder():
    """Lazily initialise and cache the tokenizer if tiktoken is available."""
    global _encoder, _tiktoken_available
    if not _tiktoken_available:
        return None
    if _encoder is None:
        try:
            import tiktoken
            _encoder = tiktoken.get_encoding(_ENCODING_NAME)
        except Exception as exc:
            logger.warning("Failed to load tiktoken encoding '%s': %s", _ENCODING_NAME, exc)
            _tiktoken_available = False
            return None
    return _encoder


def count_tokens(text: str) -> int:
    """Return the number of tokens in *text*."""
    if not text:
        return 0
    enc = _get_encoder()
    if enc is not None:
        return len(enc.encode(text))
    # Conservative fallback for JSON / structured logs (~3.3 characters per token)
    return max(1, int(len(text) / 3.3) + 1)


def truncate_to_tokens(text: str, max_tokens: int) -> str:
    """Truncate *text* so it fits within *max_tokens*."""
    if not text or max_tokens <= 0:
        return ""
    enc = _get_encoder()
    if enc is not None:
        tokens = enc.encode(text)
        if len(tokens) <= max_tokens:
            return text
        return enc.decode(tokens[:max_tokens])
    # Fallback truncation using conservative ratio
    approx_chars = int(max_tokens * 3.3)
    return text[:approx_chars]


