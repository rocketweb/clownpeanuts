"""Trap layer orchestrator.

Coordinates classifier + token factory + canary template library.
Given the last user turn, returns a routing decision that tells the
vuln_llm service emulator how to respond.

Spec: hueydeweylouie/docs/HUEYDEWEYLOUIE-SPEC.md §5.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from clownpeanuts.personas.traps.classifier import (
    ClassifierVerdict,
    HeuristicClassifier,
)
from clownpeanuts.personas.traps.templates import (
    CanaryTemplate,
    CanaryTemplateLibrary,
)
from clownpeanuts.personas.traps.tokens import IssuedToken, TokenFactory


@dataclass(frozen=True, slots=True)
class RouteDecision:
    """Result of trap-layer routing for a single turn."""

    action: str  # passthrough | escalate_probing | canary_response
    verdict: ClassifierVerdict
    response_text: str = ""
    issued_tokens: tuple[IssuedToken, ...] = ()
    template_name: str = ""


class TrapLayer:
    """Coordinates classifier + token factory + canary templates for vuln_llm."""

    def __init__(
        self,
        classifier: HeuristicClassifier,
        token_factory: TokenFactory,
        canary_library: CanaryTemplateLibrary,
    ) -> None:
        self.classifier = classifier
        self.tokens = token_factory
        self.canaries = canary_library

    @classmethod
    def from_pack(
        cls,
        pack_dir: Path,
        *,
        namespace: str = "hdl",
    ) -> "TrapLayer":
        return cls(
            classifier=HeuristicClassifier.from_pack(pack_dir),
            token_factory=TokenFactory.from_pack(pack_dir, namespace=namespace),
            canary_library=CanaryTemplateLibrary.from_pack(pack_dir),
        )

    def route(
        self,
        *,
        session_id: str,
        turn_n: int,
        last_user_text: str,
    ) -> RouteDecision:
        verdict = self.classifier.classify(last_user_text)

        if verdict.label == "benign":
            return RouteDecision(action="passthrough", verdict=verdict)

        if verdict.label == "probing":
            return RouteDecision(action="escalate_probing", verdict=verdict)

        # jailbreak_attempt | exploit_chain → canary route
        template = self.canaries.select(session_id, turn_n)
        issued: list[IssuedToken] = []
        for template_id in template.token_template_ids:
            issued.append(
                self.tokens.issue(template_id, session_id=session_id)
            )
        rendered = CanaryTemplateLibrary.render(template, issued)
        return RouteDecision(
            action="canary_response",
            verdict=verdict,
            response_text=rendered,
            issued_tokens=tuple(issued),
            template_name=template.name,
        )
