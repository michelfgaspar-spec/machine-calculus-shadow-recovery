#!/usr/bin/env python3
"""Compare a reconstructed PDF with hashes of the pinned book using Poppler."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


REFERENCE_SHA256 = "d0c6b2f625074e0bc42d43ef92898478610d8eb47aea964ce9a765f555186539"


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def run(command):
    return subprocess.run(command, check=True, capture_output=True, timeout=300,
                          env=dict(os.environ, LC_ALL="C"))


def page_count(path):
    info = run(["pdfinfo", str(path)]).stdout.decode("utf-8", errors="replace")
    match = re.search(r"^Pages:\s+(\d+)\s*$", info, re.MULTILINE)
    if not match:
        raise ValueError("pdfinfo returned no page count")
    return int(match.group(1))


def load_fingerprint(path):
    fingerprint = json.loads(path.read_text(encoding="utf-8"))
    try:
        valid_hash = lambda value: isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
        rendered = fingerprint["render"]
        valid = (
            fingerprint["schema_version"] == 1
            and fingerprint["edition"] == "structural-2026-09-26"
            and fingerprint["reference_pdf_sha256"] == REFERENCE_SHA256
            and fingerprint["expected_pages"] == 242
            and fingerprint["text_method"] == "pdftotext -layout -enc UTF-8"
            and valid_hash(fingerprint["text_sha256"])
            and rendered["method"] == "pdftoppm -r 72 -gray"
            and rendered["dpi"] == 72 and rendered["mode"] == "gray"
            and isinstance(rendered["renderer"], str)
            and isinstance(rendered["page_sha256"], list)
            and len(rendered["page_sha256"]) == 242
            and all(valid_hash(value) for value in rendered["page_sha256"])
        )
    except (KeyError, TypeError):
        valid = False
    if not valid:
        raise ValueError("Invalid fingerprint for the pinned 242-page edition")
    return fingerprint


def compare(fingerprint_path, candidate, render=False):
    fingerprint = load_fingerprint(fingerprint_path)
    for command in ["pdfinfo", "pdftotext"] + (["pdftoppm"] if render else []):
        if not shutil.which(command):
            raise ValueError("Required comparison tool is unavailable: " + command)
    candidate_pages = page_count(candidate)
    text_hash = hashlib.sha256(run([
        "pdftotext", "-layout", "-enc", "UTF-8", str(candidate), "-"
    ]).stdout).hexdigest()
    candidate_hash = digest(candidate)
    result = {
        "schema_version": 1,
        "comparison_source": "stored reference fingerprints; no reference PDF required",
        "fingerprint_sha256": digest(fingerprint_path),
        "reference_sha256": fingerprint["reference_pdf_sha256"],
        "candidate_sha256": candidate_hash,
        "reference_pages": fingerprint["expected_pages"],
        "candidate_pages": candidate_pages,
        "page_count_matches": candidate_pages == fingerprint["expected_pages"],
        "extracted_text_matches": text_hash == fingerprint["text_sha256"],
        "reference_text_sha256": fingerprint["text_sha256"],
        "candidate_text_sha256": text_hash,
        "text_method": "pdftotext -layout -enc UTF-8",
        "pdf_bytes_match": fingerprint["reference_pdf_sha256"] == candidate_hash,
        "render_check": {"performed": False},
        "scope": "Production reconstruction checks; no mathematical proof validation.",
    }
    if render:
        with tempfile.TemporaryDirectory(prefix="book-render-check-") as temporary:
            directory = Path(temporary)
            run(["pdftoppm", "-r", "72", "-gray", str(candidate), str(directory / "page")])
            pages = sorted(directory.glob("page-*.pgm"), key=lambda p: int(p.stem.split("-")[-1]))
            actual = [digest(page) for page in pages]
            expected = fingerprint["render"]["page_sha256"]
            mismatches = [i + 1 for i in range(max(len(actual), len(expected)))
                          if i >= len(actual) or i >= len(expected) or actual[i] != expected[i]]
            result["render_check"] = {
                "performed": True,
                "method": "pdftoppm -r 72 -gray; exact SHA-256 comparison of each PGM",
                "reference_pages_rendered": len(expected),
                "candidate_pages_rendered": len(actual),
                "mismatched_pages": mismatches,
                "all_pages_match": len(actual) == len(expected) == 242 and not mismatches,
                "reference_renderer": fingerprint["render"]["renderer"],
                "renderer": run(["pdftoppm", "-v"]).stderr.decode("utf-8").splitlines()[0],
            }
    result["pass"] = (result["page_count_matches"] and result["extracted_text_matches"]
                      and (not render or result["render_check"]["all_pages_match"]))
    return result

