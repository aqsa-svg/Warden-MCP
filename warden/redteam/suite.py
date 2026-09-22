"""Scenario assembly: canary minting and poisoned document construction."""

from __future__ import annotations

from typing import Final, NamedTuple

from warden.demo_server.corpus import CLEAN_DOCUMENTS, Document
from warden.redteam.canary import mint
from warden.redteam.payloads import TEMPLATES, PayloadTemplate, build_document

SUITE_SEED: Final = "warden-redteam-v1"
"""Committed. Changing it regenerates every canary, which invalidates suite.json."""

POISONED_ID_PREFIX: Final = "KB"

BY_SCENARIO: Final[dict[str, PayloadTemplate]] = {
    template.scenario_id: template for template in TEMPLATES
}


def canary_for(scenario_id: str) -> str:
    return mint(scenario_id, SUITE_SEED)


def payload_doc_id() -> str:
    """Continues the clean corpus numbering, so nothing about the id marks the
    document as special. An agent that could spot the payload by its identifier
    would not be demonstrating anything."""
    return f"{POISONED_ID_PREFIX}-{len(CLEAN_DOCUMENTS) + 1:03d}"


def build_payload(template: PayloadTemplate) -> Document:
    """The poisoned article for a template.

    Takes the template rather than an id so a caller holding a modified template --
    preflight checking a variant, a test breaking one invariant -- gets that
    template's payload rather than the registered one.

    A replacing template's payload takes the id it replaces, so it substitutes into
    that document's exact corpus slot. An appending template gets the next free id.
    """
    doc_id = template.replaces if template.replaces is not None else payload_doc_id()
    return build_document(template, canary_for(template.scenario_id), doc_id)


def poisoned_document(scenario_id: str) -> Document:
    return build_payload(BY_SCENARIO[scenario_id])


class CorpusMods(NamedTuple):
    """How a scenario modifies the demo corpus. Exactly one list is ever non-empty."""

    appends: tuple[Document, ...] = ()
    replacements: tuple[Document, ...] = ()


def corpus_mods_for_template(template: PayloadTemplate) -> CorpusMods:
    payload = build_payload(template)
    if template.replaces is not None:
        return CorpusMods(replacements=(payload,))
    return CorpusMods(appends=(payload,))


def corpus_mods_for(scenario_id: str | None) -> CorpusMods:
    if scenario_id is None or scenario_id not in BY_SCENARIO:
        return CorpusMods()
    return corpus_mods_for_template(BY_SCENARIO[scenario_id])


def customer_overrides_for(scenario_id: str | None) -> dict[str, dict[str, str]]:
    """Data-channel poison for a scenario. Empty for document scenarios and None."""
    from warden.redteam.argument_attacks import BY_SCENARIO as ARG, customer_overrides

    if scenario_id is None or scenario_id not in ARG:
        return {}
    return customer_overrides(ARG[scenario_id])


def task_for(scenario_id: str | None) -> str | None:
    """The scenario's task, or None to use the agent's default. Argument attacks need
    a task that legitimately requires the target tool; document attacks use default."""
    from warden.redteam.argument_attacks import BY_SCENARIO as ARG

    if scenario_id is None or scenario_id not in ARG:
        return None
    return ARG[scenario_id].task
