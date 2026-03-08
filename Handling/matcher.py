from __future__ import annotations

import time
from typing import Any, Callable, Optional

try:
    import pyahocorasick
    AHOCORASICK_AVAILABLE = True
except ImportError:
    AHOCORASICK_AVAILABLE = False


class PatternMatcher:
    """Aho-Corasick automaton for O(n+z) multi-pattern matching.

    Extracted from sniffer so tests exercise the production class directly
    without pulling in scapy or other capture-side dependencies.
    """

    def __init__(
        self,
        rules: list[dict[str, Any]],
        on_error: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.rules = rules
        self._folded_patterns: list[str] = [r["pattern"].casefold() for r in rules]
        self.use_ahocorasick = AHOCORASICK_AVAILABLE
        self.automaton = None
        self._on_error = on_error

        if self.use_ahocorasick:
            self.automaton = pyahocorasick.Automaton()
            for idx, rule in enumerate(rules):
                pattern = self._folded_patterns[idx]
                if not pattern:
                    # An empty needle matches at every position; skip it so it
                    # can't swamp detection or corrupt the automaton.
                    continue
                self.automaton.add_word(pattern, (idx, rule))
            self.automaton.make_automaton()

    def find_matches(self, payload: str, dst_port: int) -> tuple[Optional[dict], float]:
        detection_start = time.time()

        try:
            payload_folded = payload.casefold()

            if self.use_ahocorasick:
                assert self.automaton is not None
                for _, (_, rule) in self.automaton.iter(payload_folded):
                    if dst_port in rule["ports"]:
                        return rule, time.time() - detection_start
            else:
                # Match Aho-Corasick semantics: return the rule whose pattern
                # ends earliest in the payload, not merely the first by list order.
                best_rule = None
                best_end = None
                for idx, rule in enumerate(self.rules):
                    pattern = self._folded_patterns[idx]
                    if not pattern or dst_port not in rule["ports"]:
                        continue
                    pos = payload_folded.find(pattern)
                    if pos == -1:
                        continue
                    end = pos + len(pattern) - 1
                    if best_end is None or end < best_end:
                        best_end = end
                        best_rule = rule
                if best_rule is not None:
                    return best_rule, time.time() - detection_start

            return None, time.time() - detection_start

        except Exception as e:
            if self._on_error is not None:
                self._on_error(f"Error during pattern matching: {e}")
            return None, time.time() - detection_start
