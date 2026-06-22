"""Generation-parameter clamping in the vuln_llm emulator (M2 + L8 hardening)."""

from __future__ import annotations

from clownpeanuts.services.vuln_llm.emulator import Emulator


def _merge(request: dict) -> object:
    return Emulator()._merge_gen_params(request)


def test_max_tokens_is_clamped_to_ceiling() -> None:
    params = _merge({"max_tokens": 100_000_000})
    assert params.max_tokens <= Emulator._MAX_OUTPUT_TOKENS


def test_max_tokens_floor_and_bool_rejected() -> None:
    assert _merge({"max_tokens": -5}).max_tokens == 1
    # bool is an int subclass; it must not be treated as a token count.
    defaults = Emulator()._gen_defaults
    assert _merge({"max_tokens": True}).max_tokens == defaults.max_tokens


def test_temperature_and_top_p_are_range_clamped() -> None:
    params = _merge({"temperature": 999.0, "top_p": 5.0})
    assert 0.0 <= params.temperature <= 2.0
    assert 0.0 <= params.top_p <= 1.0
    low = _merge({"temperature": -3.0, "top_p": -1.0})
    assert low.temperature == 0.0
    assert low.top_p == 0.0


def test_stop_list_filtered_to_strings_and_capped() -> None:
    params = _merge({"stop": ["a", 1, None, "b"] + ["x"] * 50})
    assert all(isinstance(s, str) for s in params.stop)
    assert len(params.stop) <= Emulator._MAX_STOP_SEQUENCES


def test_non_list_stop_falls_back_to_defaults() -> None:
    defaults = Emulator()._gen_defaults
    assert _merge({"stop": "not-a-list"}).stop == defaults.stop
