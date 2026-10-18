"""
Rule Manager — loads, validates, and provides access to DLP policy rules.

Reads the ``config/policies.yaml`` file and exposes the parsed rules,
file policy, and scan settings to the rest of the application.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from policy.models import RuleDefinition

logger = logging.getLogger(__name__)


class RuleManager:
    """Loads and manages DLP policy rules from a YAML configuration file.

    Usage::

        manager = RuleManager()
        manager.load("config/policies.yaml")
        rules = manager.get_all()
    """

    def __init__(self) -> None:
        self._raw_config: dict[str, Any] = {}
        self._rules: list[dict[str, Any]] = []
        self._file_policy: dict[str, Any] = {}
        self._scan_settings: dict[str, Any] = {}

    def load(self, config_path: str | Path = "config/policies.yaml") -> None:
        """Load and validate rules from a YAML configuration file.

        Args:
            config_path: Path to the policies YAML file.

        Raises:
            FileNotFoundError: If the config file does not exist.
            ValueError:        If required fields are missing from rules.
        """
        config_path = Path(config_path)
        if not config_path.exists():
            raise FileNotFoundError(f"Policy config not found: {config_path}")

        with open(config_path, "r", encoding="utf-8") as fh:
            self._raw_config = yaml.safe_load(fh) or {}

        self._rules = self._raw_config.get("rules", [])
        self._file_policy = self._raw_config.get("file_policy", {})
        self._scan_settings = self._raw_config.get("scan_settings", {})

        # Validate each rule has required fields.
        self._validate_rules()

        logger.info(
            "Loaded %d policy rules from %s (org: %s)",
            len(self._rules),
            config_path,
            self._raw_config.get("organization", "unknown"),
        )

    def _validate_rules(self) -> None:
        """Validate that each rule has the minimum required fields."""
        valid_types = {"regex", "keyword", "presidio_builtin", "file_extension"}

        for i, rule in enumerate(self._rules):
            rule_id = rule.get("id")
            if not rule_id:
                raise ValueError(f"Rule at index {i} is missing 'id'")

            rule_type = rule.get("type")
            if rule_type not in valid_types:
                raise ValueError(
                    f"Rule '{rule_id}' has invalid type '{rule_type}'. "
                    f"Expected one of: {valid_types}"
                )

            if rule_type == "regex" and not rule.get("pattern"):
                raise ValueError(f"Regex rule '{rule_id}' is missing 'pattern'")

            if rule_type == "keyword" and not rule.get("keywords"):
                raise ValueError(f"Keyword rule '{rule_id}' is missing 'keywords'")

            if rule_type == "presidio_builtin" and not rule.get("entity"):
                raise ValueError(f"Builtin rule '{rule_id}' is missing 'entity'")

            if rule_type == "file_extension" and not rule.get("extensions"):
                raise ValueError(f"File extension rule '{rule_id}' is missing 'extensions'")

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    def get_all(self) -> list[RuleDefinition]:
        """Return all rules as a list of :class:`RuleDefinition` models."""
        return [
            RuleDefinition(
                id=r["id"],
                name=r.get("name", r["id"]),
                description=r.get("description", ""),
                type=r["type"],
                severity=r.get("severity", "MEDIUM"),
                action=r.get("action", "BLOCK"),
            )
            for r in self._rules
        ]

    def get_raw_rules(self) -> list[dict[str, Any]]:
        """Return raw rule dicts (needed by the scanner pipeline)."""
        return list(self._rules)

    def get_policies_dict(self) -> dict[str, Any]:
        """Return the full parsed config dict (needed by DLPAnalyzer)."""
        return dict(self._raw_config)

    def get_file_policy(self) -> dict[str, Any]:
        """Return file policy settings.

        Keys: ``max_size_bytes``, ``allowed_types``,
        ``encrypted_file_action``, ``unsupported_type_action``,
        ``extraction_timeout_seconds``.
        """
        return dict(self._file_policy)

    def get_scan_settings(self) -> dict[str, Any]:
        """Return scan settings.

        Keys: ``ocr_enabled``, ``ocr_languages``,
        ``confidence_threshold``.
        """
        return dict(self._scan_settings)


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

_default_manager: RuleManager | None = None


def get_rule_manager(config_path: str | Path = "config/policies.yaml") -> RuleManager:
    """Return a singleton RuleManager, loading from disk on first call."""
    global _default_manager
    if _default_manager is None:
        _default_manager = RuleManager()
        _default_manager.load(config_path)
    return _default_manager
