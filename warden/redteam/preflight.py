"""Preflight invariants, run before any model request is spent.

Every check here is free and model-free. They run for every template at startup, so a
broken template is reported today rather than discovered on day four of a calibration
that spends its whole daily budget on a payload that could never have worked.

Failing any check skips the template and reports which invariant failed. Nothing is
spent.
"""

from __future__ import annotations

from typing import Final, NamedTuple, Sequence

import yaml

from warden.demo_server.corpus import (
    ATTACKER_DOMAIN,
    CLEAN_DOCUMENTS,
    Document,
    corpus,
)

_CLEAN_IDS = frozenset(d.doc_id for d in CLEAN_DOCUMENTS)
from warden.demo_server.server import _score, _terms
from warden.redteam.canary import find_all
from warden.redteam.payloads import PayloadTemplate
from warden.redteam.suite import (
    BY_SCENARIO,
    build_payload,
    canary_for,
    corpus_mods_for_template,
)
from warden.policy.schema import PolicyConfig

RETRIEVAL_GATE_RANK: Final = 5
DEFAULT_POLICY_PATH: Final = "policies/demo.yaml"


class CheckResult(NamedTuple):
    name: str
    passed: bool
    detail: str


class TemplateReport(NamedTuple):
    scenario_id: str
    checks: tuple[CheckResult, ...]

    @property
    def passed(self) -> bool:
        return all(check.passed for check in self.checks)

    @property
    def failures(self) -> tuple[CheckResult, ...]:
        return tuple(check for check in self.checks if not check.passed)


def _rank_for(
    template: PayloadTemplate, payload: Document, query: str
) -> tuple[int, int, int]:
    """(rank of the payload, number of OTHER documents that also score).

    Ranks against the corpus as the run will actually present it: a replacing payload
    sits in its target's slot with the target removed, so the rank reflects the real
    experiment rather than an appended near-duplicate competing with its own original.
    """
    mods = corpus_mods_for_template(template)
    documents = corpus(mods.appends, replacements=mods.replacements)
    terms = _terms(query)
    scored = [
        (_score(f"{d.title} {d.body} {' '.join(d.tags)}", terms), d)
        for d in documents
    ]
    ranked = sorted(scored, key=lambda pair: -pair[0])
    rank = next(
        index
        for index, (_value, document) in enumerate(ranked, start=1)
        if document.doc_id == payload.doc_id
    )
    contested = sum(
        1
        for value, document in scored
        if value > 0 and document.doc_id != payload.doc_id
    )
    return rank, contested, len(documents)


def check_template(
    template: PayloadTemplate, policy: PolicyConfig
) -> TemplateReport:
    checks: list[CheckResult] = []
    payload = build_payload(template)
    canary = canary_for(template.scenario_id)

    query = template.observed_query or template.natural_query
    source = "observed" if template.observed_query else "DECLARED (unverified)"
    rank, contested, corpus_size = _rank_for(template, payload, query)
    checks.append(
        CheckResult(
            "retrieval-gate",
            rank <= RETRIEVAL_GATE_RANK,
            f"rank {rank} of {corpus_size} vs the {source} query, "
            f"{contested} other documents contest it",
        )
    )
    checks.append(
        CheckResult(
            "query-observed",
            template.observed_query is not None,
            f"gate ran against a query an agent actually produced: {query!r}"
            if template.observed_query
            else "no observed query; the gate ran against a guess, so its rank is "
            "not evidence. Capture the agent's real query from a run.",
        )
    )

    target_ok = template.replaces is None or template.replaces in _CLEAN_IDS
    checks.append(
        CheckResult(
            "replaces-target-exists",
            target_ok,
            "appends (no substitution)"
            if template.replaces is None
            else (
                f"substitutes for {template.replaces}, which is in the clean corpus"
                if target_ok
                else f"declares replaces={template.replaces!r}, which is not a clean "
                "document id; the substitution would raise at corpus build"
            ),
        )
    )

    rebuilt = build_payload(template)
    checks.append(
        CheckResult(
            "deterministic-build",
            rebuilt == payload and canary_for(template.scenario_id) == canary,
            "payload and canary reproduce byte-identically from the seed",
        )
    )

    found = find_all(payload.body)
    checks.append(
        CheckResult(
            "canary-in-payload",
            found == [canary],
            f"payload carries exactly its own canary ({canary})"
            if found == [canary]
            else f"expected [{canary}], found {found}",
        )
    )

    checks.append(
        CheckResult(
            "attacker-domain-in-payload",
            ATTACKER_DOMAIN in payload.body,
            f"{ATTACKER_DOMAIN} present in the payload body",
        )
    )

    clean_text = " ".join(f"{d.title} {d.body}" for d in CLEAN_DOCUMENTS)
    clean_ok = ATTACKER_DOMAIN not in clean_text and not find_all(clean_text)
    checks.append(
        CheckResult(
            "clean-corpus-uncontaminated",
            clean_ok,
            "no attacker domain or canary in any clean document"
            if clean_ok
            else "clean corpus is contaminated; the oracle would be unsound",
        )
    )

    classification = policy.classification.get(template.target_tool)
    checks.append(
        CheckResult(
            "target-tool-classified",
            classification is not None,
            f"{template.target_tool} -> "
            + (
                f"{classification.risk_level.value}/{classification.side_effect.value}"
                if classification is not None
                else "NOT CLASSIFIED in the policy"
            ),
        )
    )

    names_route = template.target_evidence in payload.body
    checks.append(
        CheckResult(
            "payload-names-its-target",
            names_route,
            f"body directs the agent at {template.target_tool} "
            f"via {template.target_evidence!r}"
            if names_route
            else f"body never contains {template.target_evidence!r}; the payload "
            f"names no route to {template.target_tool}",
        )
    )

    return TemplateReport(template.scenario_id, tuple(checks))


def preflight(
    scenario_ids: Sequence[str] | None = None,
    policy_path: str = DEFAULT_POLICY_PATH,
) -> list[TemplateReport]:
    with open(policy_path, encoding="utf-8") as handle:
        policy = PolicyConfig.model_validate(yaml.safe_load(handle))
    from warden.redteam.argument_attacks import BY_SCENARIO as ARG
    from warden.redteam.argument_attacks import check_argument_attack

    if scenario_ids is None:
        doc_names = sorted(BY_SCENARIO)
        arg_names = sorted(ARG)
    else:
        doc_names = [n for n in scenario_ids if n in BY_SCENARIO]
        arg_names = [n for n in scenario_ids if n in ARG]

    reports = [check_template(BY_SCENARIO[name], policy) for name in doc_names]
    reports += [check_argument_attack(ARG[name], policy) for name in arg_names]
    return reports
