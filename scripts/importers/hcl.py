"""
hcl.py — small HCL serialization helpers shared by every generator.

Not a full HCL emitter — just the handful of primitives the importers need
to render strings, lists, maps, and heredocs in a way that round-trips
through `terraform fmt`.
"""

from __future__ import annotations

import re
from typing import Any, Iterable


def esc(value: str) -> str:
    """Escape a string for inclusion in an HCL "..." literal."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def slug(name: str, *, fallback: str = "imported") -> str:
    """
    Normalize an arbitrary Kibana name into a valid HCL identifier.

    HCL identifiers must start with a letter or underscore; we prefix with
    `rule_` if the slug starts with a digit so the generator output is
    always parseable.
    """
    s = re.sub(r"[^a-zA-Z0-9]+", "_", name.lower()).strip("_") or fallback
    if s[0].isdigit():
        s = f"r_{s}"
    return s


def heredoc(value: str, *, tag: str = "EOT", indent: int = 4) -> list[str]:
    """Render a multi-line value as an indented heredoc."""
    pad = " " * indent
    lines = [f"<<-{tag}"]
    for line in value.splitlines() or [""]:
        lines.append(f"{pad}{line}")
    lines.append(f"{pad[:-2]}{tag}")
    return lines


def render_string(value: str | None, *, multiline_threshold: int = 90) -> str:
    """Quoted string OR heredoc depending on length / newlines."""
    if value is None:
        return "null"
    if "\n" in value or len(value) > multiline_threshold:
        return "\n".join(heredoc(value, indent=4))
    return f'"{esc(value)}"'


def render_list_strings(items: Iterable[str], *, indent: int = 2) -> str:
    """Render `[...]` of strings, one per line, suitable for fmt."""
    items = list(items)
    if not items:
        return "[]"
    pad = " " * (indent + 2)
    body = ",\n".join(f'{pad}"{esc(i)}"' for i in items)
    return "[\n" + body + ",\n" + " " * indent + "]"


def render_scalar(value: Any) -> str:
    """Render a scalar (str/int/float/bool/None) as HCL."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return render_string(value)
    raise TypeError(f"unsupported scalar type: {type(value).__name__}")


def banner(*lines: str, width: int = 78) -> list[str]:
    """Render a `# ===…` comment banner."""
    bar = "# " + "=" * (width - 2)
    out = [bar]
    for line in lines:
        out.append(f"# {line}" if line else "#")
    out.append(bar)
    return out
