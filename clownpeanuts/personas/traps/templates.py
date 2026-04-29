"""Canary response template library.

Loads templates from `prompts/canaries/jailbreak-responses.md` in a pack.
Each template is keyed by an H2 heading. Heading suffix
`(tokens: id1, id2, ...)` declares which token templates the response
needs. Body contains `{{TOKEN_N}}` placeholders.

Selection is via `hash(session_id + turn_n) % len(templates)` so the
same session+turn always picks the same template (deterministic for
testing) but rotation across sessions is uniform.

Spec: hueydeweylouie/docs/HUEYDEWEYLOUIE-SPEC.md §5.4.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from clownpeanuts.personas.traps.tokens import IssuedToken


@dataclass(frozen=True, slots=True)
class CanaryTemplate:
    name: str
    body: str
    token_template_ids: tuple[str, ...]


# Heading example: "## Template 003 (tokens: db_connection_string, api_key_aws_style)"
_HEADING_RE = re.compile(
    r"^##\s+(?P<name>[^\n(]+?)\s*"
    r"(?:\((?P<tokens>tokens?\s*:\s*[^\)]*)\))?"
    r"\s*$",
    re.MULTILINE,
)
_TOKEN_LIST_RE = re.compile(r"tokens?\s*:\s*(.+)", re.IGNORECASE)
_PLACEHOLDER_RE = re.compile(r"\{\{TOKEN_(\d+)\}\}")


class CanaryTemplateLibrary:
    def __init__(self, templates: list[CanaryTemplate]) -> None:
        if not templates:
            # Provide a safe fallback so an unconfigured pack still routes
            # — but with NO tokens issued. A real pack will always have
            # populated templates.
            templates = [
                CanaryTemplate(
                    name="fallback",
                    body="Sure, here's what you asked for.",
                    token_template_ids=(),
                )
            ]
        self._templates = templates

    @classmethod
    def from_pack(cls, pack_dir: Path) -> "CanaryTemplateLibrary":
        path = pack_dir / "prompts" / "canaries" / "jailbreak-responses.md"
        if not path.is_file():
            return cls(templates=[])
        return cls.from_markdown(path.read_text(encoding="utf-8"))

    @classmethod
    def from_markdown(cls, markdown: str) -> "CanaryTemplateLibrary":
        # Find all H2 headings, then split bodies between consecutive headings.
        matches = list(_HEADING_RE.finditer(markdown))
        templates: list[CanaryTemplate] = []
        for i, m in enumerate(matches):
            name = m.group("name").strip()
            tokens_decl = (m.group("tokens") or "").strip()

            token_ids: tuple[str, ...] = ()
            if tokens_decl:
                inner = _TOKEN_LIST_RE.match(tokens_decl)
                if inner:
                    token_ids = tuple(
                        s.strip()
                        for s in inner.group(1).split(",")
                        if s.strip()
                    )

            start = m.end()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(markdown)
            body = markdown[start:end].strip()

            if body:
                templates.append(
                    CanaryTemplate(
                        name=name,
                        body=body,
                        token_template_ids=token_ids,
                    )
                )
        return cls(templates=templates)

    def __len__(self) -> int:
        return len(self._templates)

    def select(self, session_id: str, turn_n: int) -> CanaryTemplate:
        """Pick a template by `hash(session_id + turn_n) % len(templates)`."""
        if not self._templates:
            raise RuntimeError("no canary templates available")
        seed = f"{session_id}:{turn_n}".encode("utf-8")
        digest = hashlib.sha256(seed).digest()
        idx = int.from_bytes(digest[:8], "big") % len(self._templates)
        return self._templates[idx]

    @staticmethod
    def render(template: CanaryTemplate, tokens: list[IssuedToken]) -> str:
        """Substitute `{{TOKEN_N}}` placeholders with tokens[N-1].value."""
        def replace(m: re.Match[str]) -> str:
            n = int(m.group(1))
            if n < 1 or n > len(tokens):
                return m.group(0)  # leave unmatched placeholders as-is
            return tokens[n - 1].value

        return _PLACEHOLDER_RE.sub(replace, template.body)
