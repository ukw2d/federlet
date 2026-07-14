"""Generic URL helpers for host-supplied federation coordinates.

federlet hardcodes no paths (see ADR-005 section 4.1). `well_known_url` only
joins a caller-supplied base with a caller-supplied path so hosts get one
canonical joiner instead of reimplementing slash handling for seed, manifest,
or well-known URLs.
"""

from __future__ import annotations

from urllib.parse import urlsplit


def well_known_url(base_url: str, path: str) -> str:
    """Join a base URL with a caller-supplied path.

    The caller always supplies `path`; federlet never invents one. Scheme and
    host come from `base_url` and are preserved. Leading/trailing slashes are
    normalized so exactly one separator joins the two parts. If `path` is
    already an absolute URL (has its own scheme), it is returned unchanged. An
    empty `path` yields `base_url` with no trailing slash.

    Raises `ValueError` if `base_url` is not an absolute URL (scheme + host).
    """
    if urlsplit(path).scheme:
        return path
    split = urlsplit(base_url)
    if not split.scheme or not split.netloc:
        raise ValueError(f"base_url must be an absolute URL: {base_url!r}")
    base = base_url.rstrip("/")
    suffix = path.lstrip("/")
    return f"{base}/{suffix}" if suffix else base
