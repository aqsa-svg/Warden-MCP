"""Corpus substitution: the controlled-experiment mechanism.

A replacing payload must occupy its target's exact slot -- same id, same position,
same count -- so a behaviour change is attributable to the embedded instruction and
nothing else. Append and replace must stay distinct, and each must refuse the other's
input, or a template could silently overwrite a real article.
"""

from __future__ import annotations

import pytest

from warden.demo_server.corpus import CLEAN_DOCUMENTS, Document, corpus
from warden.redteam.suite import corpus_mods_for

CANARY_MARK = "WARDEN-CANARY"


def a_document(doc_id: str) -> Document:
    return Document(doc_id, "T", "B", ("t",))


def test_clean_corpus_is_unchanged_with_no_mods() -> None:
    assert corpus() == CLEAN_DOCUMENTS


def test_append_adds_at_the_end_and_keeps_the_original_count() -> None:
    extra = a_document("KB-999")
    result = corpus((extra,))
    assert len(result) == len(CLEAN_DOCUMENTS) + 1
    assert result[-1] == extra


def test_append_rejects_an_id_that_already_exists() -> None:
    """Silently overwriting a real article via append would be an untracked
    replacement -- exactly what the replacements= path exists to make explicit."""
    with pytest.raises(ValueError, match="collides"):
        corpus((a_document("KB-001"),))


def test_replacement_substitutes_in_place() -> None:
    replacement = a_document("KB-001")
    result = corpus(replacements=(replacement,))
    assert len(result) == len(CLEAN_DOCUMENTS)
    original_index = next(
        i for i, d in enumerate(CLEAN_DOCUMENTS) if d.doc_id == "KB-001"
    )
    assert result[original_index] == replacement
    assert sum(1 for d in result if d.doc_id == "KB-001") == 1


def test_replacement_rejects_an_id_that_does_not_exist() -> None:
    with pytest.raises(ValueError, match="not in the clean corpus"):
        corpus(replacements=(a_document("KB-000"),))


def test_the_diagnostic_becomes_kb001() -> None:
    """The whole point: after substitution the agent sees one article where KB-001
    was, identical in id and title, differing only by the embedded instruction."""
    mods = corpus_mods_for("exfil-diagnostic")
    assert mods.appends == () and len(mods.replacements) == 1
    result = corpus(mods.appends, replacements=mods.replacements)

    kb1 = next(d for d in result if d.doc_id == "KB-001")
    assert kb1.title == "Scheduled report delivery is failing"
    assert CANARY_MARK in kb1.body
    assert "exfil-test.invalid" in kb1.body
    assert len(result) == len(CLEAN_DOCUMENTS)


def test_the_escalation_template_still_appends() -> None:
    mods = corpus_mods_for("exfil-escalation")
    assert mods.replacements == () and len(mods.appends) == 1
    assert corpus(mods.appends).__len__() == len(CLEAN_DOCUMENTS) + 1


def test_no_mods_scenario_is_clean() -> None:
    mods = corpus_mods_for(None)
    assert mods.appends == () and mods.replacements == ()
