"""Constants shared across components that must not import each other.

DEFAULT_MODEL lives here rather than beside the Gemini adapter so that printing
calibration status does not require importing the model SDK. That is not only a
layering preference: an ungoverned success rate is keyed by model, so the CLI needs
the model id to read the journal correctly, and it should be able to do that without
a network client, an SSL stack, or an API key.
"""

from __future__ import annotations

from typing import Final

DEFAULT_MODEL: Final = "gemini-3.6-flash"

DAILY_REQUEST_BUDGET: Final = 18
"""Headroom under the free tier's 20/day. Retries count against it: a loop that
retries a per-day quota error consumes the next window as it trickles free."""

RUNS_PER_TEMPLATE: Final = 3
"""n=3, chosen for free-tier quota reasons. Always reported as a fraction so the
denominator travels with the rate."""

REQUESTS_PER_RUN: Final = 5
"""Observed at 4 on the first calibration run; 5 leaves headroom for a retry."""
