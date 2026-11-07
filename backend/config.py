"""
Configuration for the Local AI Security Log Analyzer.

All token budgets and model settings are controlled here.
The 2 048-token window covers:  prompt + log data + carried context + model output.
"""

import os

# ---------------------------------------------------------------------------
# Ollama / Model
# ---------------------------------------------------------------------------
OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "qwen2.5:0.5b")

# ---------------------------------------------------------------------------
# Token budget  (must sum to <= 2048)
# ---------------------------------------------------------------------------
MAX_CONTEXT_TOKENS: int = 2048
SYSTEM_PROMPT_BUDGET: int = 150    # tokens for the system / instruction block
CONTEXT_CARRY_BUDGET: int = 200    # tokens for prior-findings summary
OUTPUT_TOKEN_BUDGET: int = 400     # tokens reserved for the model's reply

# Remaining capacity for actual log data per chunk:
DATA_TOKEN_BUDGET: int = (
    MAX_CONTEXT_TOKENS
    - SYSTEM_PROMPT_BUDGET
    - CONTEXT_CARRY_BUDGET
    - OUTPUT_TOKEN_BUDGET
)  # = 1298

# ---------------------------------------------------------------------------
# Upload constraints
# ---------------------------------------------------------------------------
MAX_FILE_SIZE_BYTES: int = 10 * 1024 * 1024   # 10 MB
ALLOWED_EXTENSIONS: set[str] = {".log", ".txt"}

# ---------------------------------------------------------------------------
# Reliability
# ---------------------------------------------------------------------------
OLLAMA_TIMEOUT_SECONDS: int = 120
MAX_RETRIES: int = 2
RETRY_DELAY_SECONDS: float = 2.0

# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------
HOST: str = os.getenv("HOST", "127.0.0.1")
PORT: int = int(os.getenv("PORT", "8000"))

