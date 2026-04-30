"""
persistence.py — Save / load Class Informer scan results
=========================================================
Results are stored as a JSON file next to the open database:

    /path/to/MyBinary.bndb   →   /path/to/MyBinary.class_informer.json

If the binary view has not been saved to a .bndb yet the file goes in
the system temp directory instead, named after the binary's base name.
"""

import json
import os
import tempfile

from binaryninja import BinaryView, log_info, log_warn

from .vftable import VftableInfo


# ── Path helpers ──────────────────────────────────────────────────────────────

def _results_path(bv: BinaryView) -> str:
    """
    Return the full path of the JSON results file for *bv*.

    Priority:
      1. Same directory as the .bndb file (bv.file.filename).
      2. Temp directory, using the binary's base name as a fallback.
    """
    db_path = bv.file.filename  # e.g. "/work/target.bndb" or "" if unsaved

    if db_path:
        base, _ = os.path.splitext(db_path)
        return base + ".class_informer.json"

    # Fallback: use the binary's display name (no path separators)
    safe_name = os.path.basename(bv.file.original_filename or "unknown")
    safe_name = safe_name.replace(os.sep, "_")
    return os.path.join(tempfile.gettempdir(), safe_name + ".class_informer.json")


# ── Serialisation ─────────────────────────────────────────────────────────────

def _info_to_dict(info: VftableInfo) -> dict:
    return {
        "address":           info.address,
        "col_address":       info.col_address,
        "method_count":      info.method_count,
        "class_name":        info.class_name,
        "hierarchy_string":  info.hierarchy_string,
        "inheritance_label": info.inheritance_label,
        "is_primary":        info.is_primary,
        "method_addresses":  info.method_addresses,
    }


def _dict_to_info(d: dict) -> VftableInfo:
    return VftableInfo(
        address=d["address"],
        col_address=d["col_address"],
        method_count=d["method_count"],
        class_name=d["class_name"],
        hierarchy_string=d["hierarchy_string"],
        inheritance_label=d["inheritance_label"],
        is_primary=d.get("is_primary", True),
        method_addresses=d.get("method_addresses", []),
    )


# ── Public API ────────────────────────────────────────────────────────────────

def save_results(bv: BinaryView, results: list) -> str:
    """
    Serialise *results* (list[VftableInfo]) to a JSON file derived from
    the database path.  Returns the path written, or raises on error.
    """
    path = _results_path(bv)
    payload = {
        "version": 1,
        "binary":  os.path.basename(bv.file.original_filename or ""),
        "count":   len(results),
        "vftables": [_info_to_dict(r) for r in results],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    log_info(f"[ClassInformer] Saved {len(results)} result(s) → {path}")
    return path


def load_results(bv: BinaryView) -> list:
    """
    Load previously saved results for *bv*.
    Returns list[VftableInfo], or raises FileNotFoundError / ValueError.
    """
    path = _results_path(bv)
    if not os.path.exists(path):
        raise FileNotFoundError(f"No saved results found at:\n{path}")

    with open(path, "r", encoding="utf-8") as fh:
        payload = json.load(fh)

    if payload.get("version") != 1:
        raise ValueError(f"Unsupported results file version: {payload.get('version')}")

    results = [_dict_to_info(d) for d in payload.get("vftables", [])]
    log_info(f"[ClassInformer] Loaded {len(results)} result(s) ← {path}")
    return results


def results_path_for(bv: BinaryView) -> str:
    """Return the expected save path without touching the filesystem."""
    return _results_path(bv)
