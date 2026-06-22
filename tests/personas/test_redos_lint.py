"""ReDoS lint for classifier regexes (defense-in-depth for trusted pack/operator config)."""

from __future__ import annotations

import pytest

from clownpeanuts.personas.traps.classifier import (
    _has_catastrophic_nested_quantifier as detect,
    _compile_rules,
)


@pytest.mark.parametrize(
    "pattern",
    [
        r"(a+)+",
        r"(a*)*",
        r"(.+)*",
        r"(\d+)+",
        r"(a{2,})+",
        r"(ab+)*",
        r"((x+))+",
    ],
)
def test_flags_nested_unbounded_quantifiers(pattern: str) -> None:
    assert detect(pattern) is True


@pytest.mark.parametrize(
    "pattern",
    [
        r"(ab)+",
        r"(a{2,5})+",
        r"\d+",
        r"a+b+c+",
        r"(?:abc)*",
        r"(\d+)",          # group with unbounded body but no outer quantifier
        r"(\w+)\s",
        r"foo|bar",
        r"[a-z]+",
        r"(abc)?",
        r"\(a+\)+",        # escaped parens are literals, not a group
        r"prefix_\d{4,8}",
    ],
)
def test_does_not_flag_safe_patterns(pattern: str) -> None:
    assert detect(pattern) is False


def test_compile_rules_rejects_redos_pattern() -> None:
    with pytest.raises(ValueError, match=r"ReDoS|nested unbounded quantifier"):
        _compile_rules(
            [{"name": "bad", "regex": r"(a+)+$", "score": 0.5}],
            source="operator",
            name_prefix="tenant:",
        )


def test_compile_rules_accepts_safe_pattern() -> None:
    rules = _compile_rules(
        [{"name": "ok", "regex": r"(secret|token)\s+\w+", "score": 0.5}],
        source="operator",
        name_prefix="tenant:",
    )
    assert len(rules) == 1
    assert rules[0].name == "tenant:ok"
