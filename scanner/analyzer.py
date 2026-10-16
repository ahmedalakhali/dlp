"""
DLP Content Analyzer — scans extracted text for sensitive data patterns.

Uses Microsoft Presidio AnalyzerEngine as the core detection backbone, extended
with custom recognizers derived from the organisation's policy rules.

Supported rule types:
  • regex          – compiled into Presidio PatternRecognizer instances
  • keyword        – case-insensitive keyword search (run alongside Presidio)
  • presidio_builtin – delegates to Presidio's built-in NER-backed recognizers
                       (CREDIT_CARD, EMAIL_ADDRESS, PHONE_NUMBER, etc.)

The module deliberately **never** returns the matched text itself — only
positional spans and metadata — to prevent accidental data leakage in logs
or API responses.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class Match:
    """A single sensitive-data match.

    Attributes:
        rule_id:     Policy rule that triggered this match (e.g. ``"SSN"``).
        entity_type: Presidio entity label (e.g. ``"SSN"``, ``"CREDIT_CARD"``).
        score:       Confidence score in ``[0.0, 1.0]``.
        start:       Start character offset in the source text (inclusive).
        end:         End character offset in the source text (exclusive).
    """

    rule_id: str
    entity_type: str
    score: float
    start: int
    end: int

    # Intentionally no field for the matched text.


# ---------------------------------------------------------------------------
# Internal keyword rule storage
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class _KeywordRule:
    """Stores a parsed keyword rule from the policy config."""

    rule_id: str
    keywords: list[str]
    case_sensitive: bool
    severity: str
    action: str


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------
class DLPAnalyzer:
    """Content analyzer that scans text for sensitive data using policy rules.

    Args:
        policies:             Parsed policy dict (top-level keys: ``rules``,
                              ``scan_settings``, …).
        confidence_threshold: Minimum Presidio score to include a result.
                              Defaults to ``0.7``.
    """

    def __init__(
        self,
        policies: dict[str, Any],
        confidence_threshold: float = 0.7,
    ) -> None:
        self.engine = AnalyzerEngine()
        self.threshold = confidence_threshold

        # Keyword rules are executed manually (not via Presidio).
        self._keyword_rules: list[_KeywordRule] = []

        # Mapping from Presidio built-in entity to our rule id.
        self._builtin_entity_to_rule: dict[str, str] = {}

        # Entities we explicitly request from Presidio (custom + built-in).
        self._entities: list[str] = []

        self._register_rules(policies.get("rules", []))

    # ------------------------------------------------------------------
    # Rule registration
    # ------------------------------------------------------------------
    def _register_rules(self, rules: list[dict[str, Any]]) -> None:
        """Walk the policy rules and wire up recognizers / keyword lists."""

        for rule in rules:
            rule_type = rule.get("type", "")
            rule_id = rule.get("id", "UNKNOWN")

            if rule_type == "regex":
                self._register_regex_rule(rule)
            elif rule_type == "keyword":
                self._register_keyword_rule(rule)
            elif rule_type == "presidio_builtin":
                self._register_builtin_rule(rule)
            else:
                logger.warning("Unknown rule type '%s' for rule '%s'", rule_type, rule_id)

    def _register_regex_rule(self, rule: dict[str, Any]) -> None:
        """Create and register a Presidio ``PatternRecognizer`` for a regex rule."""

        rule_id = rule["id"]
        pattern_text = rule["pattern"]
        name = rule.get("name", rule_id)

        recognizer = PatternRecognizer(
            supported_entity=rule_id,
            name=f"{rule_id}_recognizer",
            patterns=[
                Pattern(
                    name=name,
                    regex=pattern_text,
                    score=0.85,
                ),
            ],
        )
        self.engine.registry.add_recognizer(recognizer)
        self._entities.append(rule_id)
        logger.debug("Registered regex recognizer for '%s'", rule_id)

    def _register_keyword_rule(self, rule: dict[str, Any]) -> None:
        """Store a keyword rule for manual matching."""

        kw_rule = _KeywordRule(
            rule_id=rule["id"],
            keywords=rule.get("keywords", []),
            case_sensitive=rule.get("case_sensitive", False),
            severity=rule.get("severity", "MEDIUM"),
            action=rule.get("action", "BLOCK"),
        )
        self._keyword_rules.append(kw_rule)
        logger.debug(
            "Registered keyword rule '%s' with %d keywords",
            kw_rule.rule_id,
            len(kw_rule.keywords),
        )

    def _register_builtin_rule(self, rule: dict[str, Any]) -> None:
        """Map a Presidio built-in entity to our policy rule id."""

        entity = rule["entity"]
        rule_id = rule["id"]
        self._builtin_entity_to_rule[entity] = rule_id
        self._entities.append(entity)
        logger.debug(
            "Mapped Presidio built-in entity '%s' to rule '%s'", entity, rule_id
        )

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------
    def analyze(self, text: str) -> list[Match]:
        """Scan *text* and return all matches above the confidence threshold.

        Returns:
            A list of :class:`Match` instances sorted by ``start`` offset.
            The matched text is **never** included.
        """

        if not text:
            return []

        matches: list[Match] = []

        # --- Presidio (regex + built-in) -----------------------------------
        entities_to_scan = self._entities if self._entities else None
        presidio_results = self.engine.analyze(
            text=text,
            language="en",
            entities=entities_to_scan,
        )

        for result in presidio_results:
            if result.score < self.threshold:
                continue

            # Resolve rule_id: custom entities use the entity_type directly,
            # built-in entities are mapped via _builtin_entity_to_rule.
            rule_id = self._builtin_entity_to_rule.get(
                result.entity_type, result.entity_type
            )

            matches.append(
                Match(
                    rule_id=rule_id,
                    entity_type=result.entity_type,
                    score=result.score,
                    start=result.start,
                    end=result.end,
                )
            )

        # --- Keyword matching ----------------------------------------------
        matches.extend(self._run_keyword_matching(text))

        # Sort by position for deterministic output.
        matches.sort(key=lambda m: (m.start, m.end))
        return matches

    def _run_keyword_matching(self, text: str) -> list[Match]:
        """Run manual keyword matching against *text*."""

        results: list[Match] = []

        for kw_rule in self._keyword_rules:
            for keyword in kw_rule.keywords:
                flags = 0 if kw_rule.case_sensitive else re.IGNORECASE
                pattern = re.compile(re.escape(keyword), flags)

                for m in pattern.finditer(text):
                    results.append(
                        Match(
                            rule_id=kw_rule.rule_id,
                            entity_type=kw_rule.rule_id,
                            score=1.0,  # Keyword matches are always exact.
                            start=m.start(),
                            end=m.end(),
                        )
                    )

        return results


# ---------------------------------------------------------------------------
# Convenience loader
# ---------------------------------------------------------------------------
def load_analyzer(config_path: str | Path) -> DLPAnalyzer:
    """Load policies from a YAML file and return a configured :class:`DLPAnalyzer`.

    Args:
        config_path: Path to the ``policies.yaml`` configuration file.

    Returns:
        A ready-to-use :class:`DLPAnalyzer`.
    """

    config_path = Path(config_path)
    logger.info("Loading DLP policies from %s", config_path)

    with open(config_path, "r", encoding="utf-8") as fh:
        policies = yaml.safe_load(fh)

    threshold = (
        policies.get("scan_settings", {}).get("confidence_threshold", 0.7)
    )

    return DLPAnalyzer(policies=policies, confidence_threshold=threshold)
