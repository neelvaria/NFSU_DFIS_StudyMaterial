"""
Document Parser Module
Reads text from various file formats and plain text input
"""

import os
import json
import re


def parse_txt(filepath: str) -> str:
    """Read plain text file."""
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def parse_json(filepath: str) -> str:
    """Flatten JSON threat intel feed to text."""
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)
    return json.dumps(data, indent=2)


def parse_file(filepath: str) -> str:
    """
    Auto-detect file format and extract text.
    Supports: .txt, .json, .log, .csv, .md, .html
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    ext = os.path.splitext(filepath)[1].lower()

    if ext in (".txt", ".log", ".md", ".csv"):
        return parse_txt(filepath)

    elif ext == ".json":
        return parse_json(filepath)

    elif ext == ".html" or ext == ".htm":
        return parse_html(filepath)

    else:
        # Try reading as plain text anyway
        try:
            return parse_txt(filepath)
        except Exception:
            raise ValueError(f"Unsupported file format: {ext}")


def parse_html(filepath: str) -> str:
    """Strip HTML tags and return plain text."""
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        html = f.read()
    # Remove script and style blocks
    html = re.sub(r'<(script|style)[^>]*>.*?</\1>', '', html, flags=re.DOTALL | re.IGNORECASE)
    # Remove all HTML tags
    text = re.sub(r'<[^>]+>', ' ', html)
    # Collapse whitespace
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


def parse_text(raw_text: str) -> str:
    """Accept raw text directly (stdin or paste)."""
    return raw_text