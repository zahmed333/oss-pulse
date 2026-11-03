"""Small, boring, important helpers: atomic writes so a crashed job never leaves a
half-written partition that downstream readers would silently pick up."""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import Iterable
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq


def _tmp_sibling(path: Path) -> Path:
    return path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")


def atomic_write_table(table: pa.Table, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = _tmp_sibling(path)
    pq.write_table(table, tmp, compression="zstd")
    os.replace(tmp, path)
    return path


def atomic_write_json(obj: dict, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = _tmp_sibling(path)
    tmp.write_text(json.dumps(obj, indent=2, default=str))
    os.replace(tmp, path)
    return path


def atomic_write_lines(lines: Iterable[str], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = _tmp_sibling(path)
    with open(tmp, "w") as fh:
        for line in lines:
            fh.write(line + "\n")
    os.replace(tmp, path)
    return path
