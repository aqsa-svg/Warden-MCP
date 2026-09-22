"""Hard request budget for model calls.

On a free key a runaway retry loop errors out. On a paid key it spends money, so the
cap is not a convenience -- it is the difference between a bug and a bill.

Three properties, all deliberate:

  * There is no default. A caller that does not state a cap cannot start. A default
    would be a number nobody chose, applied to a money path.
  * Retries count. The 429 backoff exists so a rate limit does not record an attack
    as unsuccessful, but each retry is a billable request and must be charged.
  * The count is reported on exit whatever happened -- success, exception, or budget
    exhaustion. A run that dies still spent what it spent.
"""

from __future__ import annotations

from types import TracebackType
from typing import Callable

from warden.errors import BudgetExceeded


class RequestBudget:
    """Counts model requests against a hard ceiling."""

    def __init__(self, limit: int) -> None:
        if limit <= 0:
            raise ValueError(f"request budget must be positive, got {limit}")
        self._limit = limit
        self._spent = 0

    @property
    def limit(self) -> int:
        return self._limit

    def spent(self) -> int:
        return self._spent

    def remaining(self) -> int:
        return max(0, self._limit - self._spent)

    def charge(self, count: int = 1) -> None:
        """Charge before issuing the request, so an over-budget call is never sent."""
        if self._spent + count > self._limit:
            raise BudgetExceeded(
                f"request budget exhausted: {self._spent}/{self._limit} spent, "
                f"{count} more requested"
            )
        self._spent += count


class BudgetReporter:
    """Context manager that prints the spend on exit, however the block ended."""

    def __init__(self, budget: RequestBudget, emit: Callable[[str], None]) -> None:
        self._budget = budget
        self._emit = emit

    def __enter__(self) -> RequestBudget:
        self._emit(f"[budget] cap {self._budget.limit} model requests")
        return self._budget

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._emit(
            f"[budget] spent {self._budget.spent()}/{self._budget.limit} "
            f"model requests ({self._budget.remaining()} unused)"
        )
