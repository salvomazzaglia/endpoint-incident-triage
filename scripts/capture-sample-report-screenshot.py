#!/usr/bin/env python3
"""Capture a screenshot of the synthetic triage HTML report.

Refuses non-synthetic input. Prefers Edge/Chrome/Chromium headless; falls back
to a pure-Python PNG preview if no browser is available.
"""

from __future__ import annotations

import argparse
import struct
import subprocess
import sys
import zlib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

BROWSER_CANDIDATES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/usr/bin/microsoft-edge",
    "/snap/bin/chromium",
]


def find_browser() -> str | None:
    for path in BROWSER_CANDIDATES:
        if Path(path).is_file():
            return path
    from shutil import which

    for name in ("google-chrome", "chromium", "chromium-browser", "msedge", "microsoft-edge"):
        found = which(name)
        if found:
            return found
    return None


def verify_synthetic(html: str) -> None:
    lower = html.lower()
    if "synthetic demonstration data" not in lower:
        raise SystemExit("Refusing non-synthetic HTML: missing SYNTHETIC DEMONSTRATION DATA marker")
    if "demonstration" not in lower and "synthetic" not in lower:
        raise SystemExit("Refusing HTML without synthetic disclaimer")


def png_chunk(tag: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + tag
        + data
        + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    )


def write_fallback_png(path: Path, width: int = 1440, height: int = 1000) -> None:
    """Create a simple synthetic triage report preview PNG (no PIL)."""
    rows = []
    for y in range(height):
        row = bytearray()
        for x in range(width):
            r, g, b = 15, 23 + (y * 20) // height, 32 + (x * 25) // width
            if 80 <= y <= 160:
                r, g, b = 138, 31, 31
            if 200 <= y <= 320:
                if 40 <= x <= 200:
                    r, g, b = 47, 158, 107
                elif 240 <= x <= 400:
                    r, g, b = 201, 146, 42
                elif 440 <= x <= 600:
                    r, g, b = 194, 70, 70
            if 380 <= y <= 420:
                r, g, b = 30, 47, 66
            row.extend((r, g, b))
        rows.append(b"\x00" + bytes(row))
    raw = b"".join(rows)
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    png = (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", ihdr)
        + png_chunk(b"IDAT", zlib.compress(raw, 9))
        + png_chunk(b"IEND", b"")
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(png)


def capture_with_browser(browser: str, html_path: Path, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    uri = html_path.resolve().as_uri()
    cmd = [
        browser,
        "--headless=new",
        "--disable-gpu",
        "--hide-scrollbars",
        "--window-size=1440,1000",
        f"--screenshot={out_path}",
        uri,
    ]
    subprocess.run(cmd, check=True, capture_output=True, timeout=120)


def validate_png(path: Path) -> None:
    data = path.read_bytes()
    if len(data) < 100:
        raise SystemExit("PNG too small / empty")
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise SystemExit("Not a valid PNG")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Capture synthetic triage report screenshot")
    parser.add_argument(
        "--input",
        type=Path,
        default=REPO_ROOT / "examples" / "sample-triage-report.html",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "docs" / "images" / "sample-triage-report.png",
    )
    args = parser.parse_args(argv)

    if not args.input.is_file():
        print(f"ERROR: missing HTML input: {args.input}", file=sys.stderr)
        return 3

    html = args.input.read_text(encoding="utf-8")
    verify_synthetic(html)

    browser = find_browser()
    try:
        if browser:
            print(f"Using browser: {browser}")
            capture_with_browser(browser, args.input, args.output)
        else:
            print("No browser found; writing pure-Python synthetic PNG preview")
            write_fallback_png(args.output)
    except Exception as exc:
        print(f"Browser capture failed ({exc}); writing fallback PNG", file=sys.stderr)
        write_fallback_png(args.output)

    validate_png(args.output)
    print(f"Wrote {args.output} ({args.output.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
