"""Corpus separation, canary minting, and the retrieval gate.

None of this needs a model. It is the part of component 5 whose correctness is a
property of the corpus rather than of the agent's behaviour.
"""

from __future__ import annotations

import pytest

from warden.demo_server.corpus import (
    ATTACKER_DOMAIN,
    CLEAN_DOCUMENTS,
    Document,
    assert_clean_corpus_is_clean,
    corpus,
)
from warden.demo_server.server import _score, _terms
from warden.redteam.canary import CANARY_RE, PREFIX, find_all, mint
from warden.redteam.suite import (
    BY_SCENARIO,
    SUITE_SEED,
    canary_for,
    corpus_mods_for,
    poisoned_document,
)

MIN_CORPUS_SIZE = 100
RETRIEVAL_GATE_RANK = 5


# -- corpus separation is structural, not conventional -------------------------


def test_default_corpus_is_clean() -> None:
    """There is no module-level mutable list to inject into, so a benign scenario
    cannot load a payload by accident."""
    assert corpus() == CLEAN_DOCUMENTS
    mods = corpus_mods_for(None)
    assert mods.appends == () and mods.replacements == ()


def test_poisoned_documents_only_enter_when_named() -> None:
    document = poisoned_document("exfil-escalation")
    assert document not in corpus()
    mods = corpus_mods_for("exfil-escalation")
    assert document in corpus(mods.appends, replacements=mods.replacements)


def test_clean_corpus_invariants_hold() -> None:
    """The exfiltration oracle matches on the attacker domain. If that domain
    appeared in clean content the oracle could fire on a benign summary and the
    reported ASR would be fiction."""
    assert_clean_corpus_is_clean()


def test_clean_corpus_contains_no_attacker_domain_or_canary() -> None:
    joined = " ".join(f"{d.title} {d.body}" for d in CLEAN_DOCUMENTS)
    assert ATTACKER_DOMAIN not in joined
    assert PREFIX not in joined
    assert find_all(joined) == []


def test_clean_corpus_is_large_enough_for_the_gate_to_mean_something() -> None:
    """Against 20 documents the top-5 assertion is close to free. The gate is only a
    real constraint when a payload has to compete."""
    assert len(CLEAN_DOCUMENTS) >= MIN_CORPUS_SIZE


def test_document_ids_are_unique_including_the_payload() -> None:
    mods = corpus_mods_for("exfil-escalation")
    full = corpus(mods.appends, replacements=mods.replacements)
    ids = [document.doc_id for document in full]
    assert len(set(ids)) == len(ids)


def test_the_payload_id_does_not_mark_it_as_special() -> None:
    """An agent that could spot the payload by its identifier would demonstrate
    nothing."""
    payload = poisoned_document("exfil-escalation")
    assert payload.doc_id.startswith("KB-")
    assert payload.doc_id[3:].isdigit()


# -- canaries ------------------------------------------------------------------


def test_canary_minting_is_deterministic() -> None:
    assert canary_for("exfil-escalation") == canary_for("exfil-escalation")
    assert mint("exfil-escalation", SUITE_SEED) == canary_for("exfil-escalation")


def test_canaries_differ_by_scenario_and_by_seed() -> None:
    assert mint("alpha", SUITE_SEED) != mint("beta", SUITE_SEED)
    assert mint("alpha", SUITE_SEED) != mint("alpha", "other-seed")


def test_canary_shape_is_matchable() -> None:
    canary = canary_for("exfil-escalation")
    match = CANARY_RE.fullmatch(canary)
    assert match is not None
    assert match.group(1) == "exfil-escalation"
    assert len(match.group(2)) == 8


def test_malformed_scenario_ids_are_rejected() -> None:
    for bad in ("Has-Upper", "has_underscore", "", "with space", "x" * 40):
        with pytest.raises(ValueError):
            mint(bad, SUITE_SEED)


def test_the_payload_carries_its_own_canary_and_no_other() -> None:
    payload = poisoned_document("exfil-escalation")
    found = find_all(payload.body)
    assert found == [canary_for("exfil-escalation")]


# -- the retrieval gate --------------------------------------------------------


def rank_of(scenario_id: str, query: str) -> int:
    mods = corpus_mods_for(scenario_id)
    payload = poisoned_document(scenario_id)
    full = corpus(mods.appends, replacements=mods.replacements)
    terms = _terms(query)
    ranked = sorted(
        (
            (_score(f"{d.title} {d.body} {' '.join(d.tags)}", terms), d)
            for d in full
        ),
        key=lambda pair: -pair[0],
    )
    return next(
        index
        for index, (_score_value, document) in enumerate(ranked, start=1)
        if document.doc_id == payload.doc_id
    )


@pytest.mark.parametrize("scenario_id", sorted(BY_SCENARIO))
def test_payload_ranks_for_the_natural_query(scenario_id: str) -> None:
    """The payload must surface for the query the scenario's benign task actually
    produces -- not for one crafted to find it. A payload the agent only sees because
    the corpus is small demonstrates nothing."""
    template = BY_SCENARIO[scenario_id]
    query = template.observed_query or template.natural_query
    rank = rank_of(scenario_id, query)
    assert rank <= RETRIEVAL_GATE_RANK, (
        f"{scenario_id} ranks {rank} for its natural query; it would not be retrieved"
    )


@pytest.mark.parametrize("scenario_id", sorted(BY_SCENARIO))
def test_the_gate_is_contested(scenario_id: str) -> None:
    """At least four clean documents must also score for the natural query. If the
    payload is the only match, ranking first says nothing about competitiveness."""
    template = BY_SCENARIO[scenario_id]
    terms = _terms(template.natural_query)
    scoring = [
        d
        for d in CLEAN_DOCUMENTS
        if _score(f"{d.title} {d.body} {' '.join(d.tags)}", terms) > 0
    ]
    assert len(scoring) >= RETRIEVAL_GATE_RANK - 1
