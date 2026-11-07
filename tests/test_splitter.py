"""Unit tests for log splitting."""

from pathlib import Path
import pytest
from backend.splitter import split_log_file
from backend import config
from backend.token_utils import count_tokens

SAMPLE_LOG = Path(__file__).resolve().parent.parent / "Cultive8_Workspace_Agrigen_Server.log"


def test_splitter_chunks_cover_all_lines():
    """Verify that chunks cover lines 1 through 258 continuously with zero gaps."""
    chunks = split_log_file(SAMPLE_LOG, config.DATA_TOKEN_BUDGET)
    assert len(chunks) > 0, "Splitter should produce at least one chunk"

    total_lines = 0
    expected_start = 1

    for i, c in enumerate(chunks):
        assert c.index == i, f"Chunk index mismatch at {i}"
        assert c.start_line == expected_start, (
            f"Expected chunk {i} to start at line {expected_start}, but was {c.start_line}"
        )
        assert c.end_line >= c.start_line
        assert c.token_count <= config.DATA_TOKEN_BUDGET + 50, (
            f"Chunk {i} exceeded token budget: {c.token_count} > {config.DATA_TOKEN_BUDGET}"
        )
        total_lines += c.line_count
        expected_start = c.end_line + 1

    # In Cultive8_Workspace_Agrigen_Server.log, there are 258 lines
    assert total_lines == 258, f"Expected 258 total lines, got {total_lines}"
    assert chunks[-1].end_line == 258, f"Expected last line to be 258, got {chunks[-1].end_line}"


def test_chunk_text_annotated_with_line_numbers():
    """Verify each line in chunk text is prefixed with [L<line_no>]."""
    chunks = split_log_file(SAMPLE_LOG, config.DATA_TOKEN_BUDGET)
    first_chunk = chunks[0]

    lines = first_chunk.text.split("\n")
    assert lines[0].startswith("[L1] "), "First line should be annotated with [L1]"
    assert lines[1].startswith("[L2] "), "Second line should be annotated with [L2]"


def test_chunk_within_context_budget():
    """Verify prompt + chunk + context fits under MAX_CONTEXT_TOKENS (2,048)."""
    chunks = split_log_file(SAMPLE_LOG, config.DATA_TOKEN_BUDGET)
    for c in chunks:
        # Prompt budget = SYSTEM (150) + CONTEXT (200) + DATA chunk + OUTPUT (400) <= 2048
        # Therefore DATA chunk tokens must fit config.DATA_TOKEN_BUDGET
        assert c.token_count <= config.DATA_TOKEN_BUDGET

