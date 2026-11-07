"""
Log file splitter – chunks a log file into model-sized pieces.

Each chunk contains complete log lines annotated with their original
1-based line numbers.  Lines are never split mid-entry.
"""

from __future__ import annotations

from pathlib import Path

from backend.token_utils import count_tokens, truncate_to_tokens
from backend.models import LogChunk


def split_log_file(
    file_path: str | Path,
    data_token_budget: int,
) -> list[LogChunk]:
    """Split a log file into chunks that each fit within *data_token_budget*.

    The file is read once.  For the expected assessment file (~94 KB,
    ~258 lines) this is well within the 4 GB memory limit.
    """
    file_path = Path(file_path)
    raw_lines: list[str] = file_path.read_text(encoding="utf-8").splitlines()

    chunks: list[LogChunk] = []
    buf_lines: list[str] = []      # annotated lines in the current chunk
    buf_tokens: int = 0
    chunk_start_line: int = 1      # 1-indexed

    for line_no, raw in enumerate(raw_lines, start=1):
        stripped = raw.strip()
        if not stripped:
            continue                # skip blank lines

        annotated = f"[L{line_no}] {stripped}"
        line_tok = count_tokens(annotated + "\n")

        # ---- single line exceeds the whole budget → include it alone ----
        if line_tok > data_token_budget:
            if buf_lines:
                chunks.append(_flush(
                    len(chunks), chunk_start_line, line_no - 1,
                    buf_lines, buf_tokens,
                ))
                buf_lines, buf_tokens = [], 0

            truncated = truncate_to_tokens(annotated, data_token_budget - 10)
            chunks.append(_flush(
                len(chunks), line_no, line_no,
                [truncated], count_tokens(truncated + "\n"),
            ))
            chunk_start_line = line_no + 1
            continue

        # ---- adding this line would overflow → flush first ----
        if buf_tokens + line_tok > data_token_budget and buf_lines:
            chunks.append(_flush(
                len(chunks), chunk_start_line, line_no - 1,
                buf_lines, buf_tokens,
            ))
            buf_lines, buf_tokens = [], 0
            chunk_start_line = line_no

        buf_lines.append(annotated)
        buf_tokens += line_tok

    # ---- remaining lines ----
    if buf_lines:
        # Determine end_line: the actual last non-empty line number
        last_line = len(raw_lines)
        chunks.append(_flush(
            len(chunks), chunk_start_line, last_line,
            buf_lines, buf_tokens,
        ))

    return chunks


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------

def _flush(
    index: int,
    start_line: int,
    end_line: int,
    lines: list[str],
    tokens: int,
) -> LogChunk:
    return LogChunk(
        index=index,
        start_line=start_line,
        end_line=end_line,
        line_count=len(lines),
        token_count=tokens,
        text="\n".join(lines),
    )

