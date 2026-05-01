"""
_kibana.py — minimal Kibana REST client shared by every importer.

Pulled out of import_gui_rule.py so the bulk importer + future drift
triage tooling don't reinvent paging, auth, and JSON cache handling.

Auth model: API key only, read from KIBANA_API_KEY env var. Endpoint
read from KIBANA_ENDPOINT or passed explicitly.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterator


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
def auth_header() -> str:
    """Return the `Authorization: ApiKey ...` header value or exit."""
    api_key = os.environ.get("KIBANA_API_KEY")
    if not api_key:
        print(
            "  ✗ KIBANA_API_KEY is not set.\n"
            "     Generate one in Kibana → Stack Management → API Keys and export it:\n"
            "       export KIBANA_API_KEY=<encoded value>",
            file=sys.stderr,
        )
        sys.exit(1)
    return f"ApiKey {api_key}"


def resolve_endpoint(explicit: str | None = None) -> str:
    """Resolve KIBANA_ENDPOINT from --flag or env, stripped of trailing /."""
    kb = explicit or os.environ.get("KIBANA_ENDPOINT")
    if not kb:
        print(
            "  ✗ KIBANA_ENDPOINT is not set. Pass --kibana-url or export it.",
            file=sys.stderr,
        )
        sys.exit(1)
    return kb.rstrip("/")


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
class KibanaError(RuntimeError):
    """Wraps any non-2xx response from Kibana with the URL for context."""


def get(url: str, auth: str, *, timeout: int = 30, retries: int = 2) -> Any:
    """GET a Kibana endpoint, return decoded JSON. Retries transient errors."""
    last_err: Exception | None = None
    for attempt in range(retries + 1):
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": auth,
                "kbn-xsrf": "true",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            # 4xx is not retryable; surface the body for debugging.
            body = e.read().decode("utf-8", errors="replace") if e.fp else ""
            raise KibanaError(f"{e.code} {e.reason} on {url}\n{body}") from e
        except urllib.error.URLError as e:
            last_err = e
            if attempt < retries:
                time.sleep(1.5 * (attempt + 1))
                continue
            raise KibanaError(f"connection failed for {url}: {e}") from e
    # Unreachable, but appease the type checker.
    raise KibanaError(str(last_err))  # pragma: no cover


# ---------------------------------------------------------------------------
# Paging helpers
# ---------------------------------------------------------------------------
def paged(
    base_url: str,
    auth: str,
    *,
    per_page: int = 100,
    extra_params: dict[str, str] | None = None,
    page_param: str = "page",
    per_page_param: str = "per_page",
    data_key: str = "data",
    total_key: str = "total",
) -> Iterator[dict]:
    """
    Yield every record across paged Kibana endpoints.

    Most detection-engine and exception-list `_find` endpoints follow the
    page/per_page convention with a top-level `data[]` and `total`. The
    defaults match those; override the params for endpoints that differ.
    """
    page = 1
    while True:
        params = {page_param: str(page), per_page_param: str(per_page)}
        if extra_params:
            params.update(extra_params)
        url = f"{base_url}?{urllib.parse.urlencode(params)}"
        resp = get(url, auth)
        items = resp.get(data_key, [])
        if not items:
            return
        for item in items:
            yield item
        total = int(resp.get(total_key, 0))
        if page * per_page >= total:
            return
        page += 1


# ---------------------------------------------------------------------------
# JSON cache
# ---------------------------------------------------------------------------
def cache_dir(project_root: Path, namespace: str, dump_id: str) -> Path:
    """
    Resolve the on-disk cache dir for a dump and ensure it exists.

    Layout:
        <project_root>/.import-cache/<dump_id>/<namespace>/
    """
    d = project_root / ".import-cache" / dump_id / namespace
    d.mkdir(parents=True, exist_ok=True)
    return d


def write_cache(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))


def read_cache(path: Path) -> Any:
    return json.loads(path.read_text())
