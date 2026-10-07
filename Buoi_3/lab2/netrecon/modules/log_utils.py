"""Ghi log chung vao thu muc ung dung."""
import logging
from pathlib import Path

logger = logging.getLogger("netrecon")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.FileHandler(
        Path(__file__).resolve().parent.parent / "netrecon.log", encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)


def log(message):
    logger.info(message)
