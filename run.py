#!/usr/bin/env python3
"""Entry point for the Local AI Security Log Analyzer."""

import logging
import uvicorn
from backend.config import HOST, PORT

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%H:%M:%S",
)

if __name__ == "__main__":
    print(f"\n  Local AI Security Log Analyzer")
    print(f"  Open http://{HOST}:{PORT} in your browser\n")
    uvicorn.run(
        "backend.main:app",
        host=HOST,
        port=PORT,
        reload=False,
        log_level="info",
    )

