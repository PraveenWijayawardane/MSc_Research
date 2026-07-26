from __future__ import annotations

import re
from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml


class EnvironmentRegistryError(Exception):
    """Base exception for environment registry errors."""


class EnvironmentNotFoundError(EnvironmentRegistryError):
    """Raised when an environment does not exist."""


class EnvironmentConfigurationError(EnvironmentRegistryError):
    """Raised when an environment configuration is invalid."""


ENVIRONMENT_ID_PATTERN = re.compile(
    r"^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$"
)


def load_yaml(path: Path) -> dict[str, Any]:
    """
    Safely load a YAML file.

    Returns an empty dictionary when the YAML file is empty.
    """
    if not path.exists():
        raise EnvironmentConfigurationError(
            f"Configuration file not found: {path}"
        )

    if not path.is_file():
        raise EnvironmentConfigurationError(
            f"Configuration path is not a file: {path}"
        )

    try:
        with path.open(
            "r",
            encoding="utf-8",
        ) as file:
            content = yaml.safe_load(file)
    except yaml.YAMLError as exc:
        raise EnvironmentConfigurationError(
            f"Invalid YAML file: {path}"
        ) from exc

    if content is None:
        return {}

    if not isinstance(content, dict):
        raise EnvironmentConfigurationError(
            f"YAML root must be a dictionary: {path}"
        )

    return content


def validate_environment_id(
    environment_id: str,
) -> str:
    """
    Validate an environment ID and protect against path traversal.
    """
    environment_id = environment_id.strip().lower()

    if not ENVIRONMENT_ID_PATTERN.fullmatch(
        environment_id
    ):
        raise EnvironmentConfigurationError(
            "Environment ID must contain only lowercase "
            "letters, numbers and hyphens"
        )

    if ".." in environment_id:
        raise EnvironmentConfigurationError(
            "Environment ID contains an invalid path sequence"
        )

    return environment_id


def deep_merge(
    base: dict[str, Any],
    override: dict[str, Any],
) -> dict[str, Any]:
    """
    Recursively merge dictionaries.

    Environment-specific values override base values.
    """
    result = deepcopy(base)

    for key, value in override.items():
        existing_value = result.get(key)

        if (
            isinstance(existing_value, dict)
            and isinstance(value, dict)
        ):
            result[key] = deep_merge(
                existing_value,
                value,
            )
        else:
            result[key] = deepcopy(value)

    return result


class EnvironmentRegistry:
    """
    Load common rules and hospital-specific configurations.
    """

    def __init__(
        self,
        config_root: Path | str,
    ):
        self.config_root = Path(
            config_root
        ).resolve()

        self.base_root = (
            self.config_root
            / "base"
        )

        self.environments_root = (
            self.config_root
            / "environments"
        )

        self._cache: dict[
            str,
            dict[str, Any],
        ] = {}

    def list_environments(self) -> list[str]:
        """
        Return all configured environment IDs.
        """
        if not self.environments_root.exists():
            return []

        environments = []

        for path in self.environments_root.iterdir():
            if (
                path.is_dir()
                and (path / "environment.yaml").exists()
            ):
                environments.append(path.name)

        return sorted(environments)

    def environment_exists(
        self,
        environment_id: str,
    ) -> bool:
        """
        Check whether an environment exists.
        """
        environment_id = validate_environment_id(
            environment_id
        )

        environment_directory = (
            self.environments_root
            / environment_id
        )

        return (
            environment_directory.is_dir()
            and (
                environment_directory
                / "environment.yaml"
            ).is_file()
        )

    def load(
        self,
        environment_id: str,
        use_cache: bool = True,
    ) -> dict[str, Any]:
        """
        Load common rules and the selected environment.
        """
        environment_id = validate_environment_id(
            environment_id
        )

        if (
            use_cache
            and environment_id in self._cache
        ):
            return deepcopy(
                self._cache[environment_id]
            )

        environment_directory = (
            self.environments_root
            / environment_id
        )

        if not environment_directory.exists():
            raise EnvironmentNotFoundError(
                f"Environment not found: "
                f"{environment_id}"
            )

        environment_file = (
            environment_directory
            / "environment.yaml"
        )

        asset_context_file = (
            environment_directory
            / "asset_context.yaml"
        )

        risk_rules_file = (
            self.base_root
            / "risk_rules.yaml"
        )

        role_policies_file = (
            self.base_root
            / "role_policies.yaml"
        )

        environment_configuration = load_yaml(
            environment_file
        )

        asset_context = load_yaml(
            asset_context_file
        )

        risk_rules = load_yaml(
            risk_rules_file
        )

        role_policies = load_yaml(
            role_policies_file
        )

        configured_id = (
            environment_configuration
            .get("environment", {})
            .get("id")
        )

        if configured_id != environment_id:
            raise EnvironmentConfigurationError(
                f"Environment directory ID "
                f"'{environment_id}' does not match "
                f"environment.yaml ID "
                f"'{configured_id}'"
            )

        configuration = {
            "environment_id": environment_id,
            "schema_version": (
                environment_configuration.get(
                    "schema_version",
                    "1.0",
                )
            ),
            "environment": (
                environment_configuration.get(
                    "environment",
                    {},
                )
            ),
            "business_hours": (
                environment_configuration.get(
                    "business_hours",
                    {},
                )
            ),
            "data_sources": (
                environment_configuration.get(
                    "data_sources",
                    {},
                )
            ),
            "output": (
                environment_configuration.get(
                    "output",
                    {},
                )
            ),
            "asset_context": asset_context,
            "risk_rules": risk_rules,
            "role_policies": role_policies,
            "paths": {
                "environment_directory": str(
                    environment_directory
                ),
                "environment_file": str(
                    environment_file
                ),
                "asset_context_file": str(
                    asset_context_file
                ),
                "risk_rules_file": str(
                    risk_rules_file
                ),
                "role_policies_file": str(
                    role_policies_file
                ),
            },
        }

        self._cache[environment_id] = deepcopy(
            configuration
        )

        return deepcopy(configuration)

    def reload(
        self,
        environment_id: str,
    ) -> dict[str, Any]:
        """
        Clear cached configuration and load it again.
        """
        environment_id = validate_environment_id(
            environment_id
        )

        self._cache.pop(
            environment_id,
            None,
        )

        return self.load(
            environment_id,
            use_cache=False,
        )

    def clear_cache(self) -> None:
        """
        Clear all cached environment configurations.
        """
        self._cache.clear()