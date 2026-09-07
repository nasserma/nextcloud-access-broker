"""Markdown → HTML for the approval room (D6.1).

The bot composes markdown text; this module converts it to the
formatted_body HTML the Matrix spec wants alongside the plain body.
Element (and other clients that honor formatted_body) render bold and
code; clients that ignore formatted_body fall back to the plain text
body, which is always the full readable content.

Scope is deliberately tiny: **bold**, `inline code`, ``` fences, and
HTML escaping of everything else. No lists/links/headers — the bot
never emits them, and a small grammar is auditable (this module feeds
an approval plane; surprising input must fail visibly, not render
inventively).
"""

from __future__ import annotations

import html
import re

_BOLD_RE = re.compile(r"\*\*(.+?)\*\*", re.DOTALL)
_CODE_RE = re.compile(r"`([^`\n]+)`")


def text_to_html(text: str) -> str:
    """Escape-then-annotate: escape ALL text first (so no room content
    — paths, reasons, instance names — can inject HTML), then turn the
    bot's own ** and ` markers into tags.

    Fenced blocks: the whole fence becomes one <code> block with a
    trailing newline (Matrix clients need it to close the box).
    """
    # Split off ``` fences first so their contents are escaped but not
    # further annotated (no nested bold inside a code block).
    parts = re.split(r"(```[^\n]*\n.*?```)", text, flags=re.DOTALL)
    out = []
    for i, part in enumerate(parts):
        if i % 2 == 1:  # fenced segment (regex keeps the ``` markers in it)
            body = part
            # strip the fence lines
            body = re.sub(r"^```\w*\n", "", body)
            body = re.sub(r"\n```\s*$", "\n", body)
            out.append(
                "<pre><code>" + html.escape(body, quote=False) + "</code></pre>"
            )
        else:
            out.append(_inline_to_html(part))
    return "".join(out)


def _inline_to_html(text: str) -> str:
    escaped = html.escape(text, quote=False)
    # code first (its backticks are gone after tagging; bold markers
    # inside code spans stay literal — the bot never writes ** inside
    # `...`)
    escaped = _CODE_RE.sub(lambda m: f"<code>{m.group(1)}</code>", escaped)
    escaped = _BOLD_RE.sub(lambda m: f"<strong>{m.group(1)}</strong>", escaped)
    return escaped.replace("\n", "<br/>")