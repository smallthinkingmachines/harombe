"""Plugin permission enforcement.

Sets the `dangerous` flag on tools, integrates with HITL rules,
and bridges plugin permissions to container configurations.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from harombe.tools.registry import _TOOLS

if TYPE_CHECKING:
    from harombe.plugins.manifest import LoadedPlugin

logger = logging.getLogger(__name__)


def apply_plugin_permissions(plugin: LoadedPlugin) -> None:
    """Apply declared permissions to a plugin's tools.

    Sets the `dangerous` flag on tools based on the
    plugin's declared permissions.

    Args:
        plugin: Loaded plugin with permissions
    """
    if not plugin.manifest.permissions.dangerous:
        return

    for tool_name in plugin.tool_names:
        tool = _TOOLS.get(tool_name)
        if tool:
            tool.schema.dangerous = True
            logger.debug(
                "Marked tool '%s' from plugin '%s' as dangerous",
                tool_name,
                plugin.manifest.name,
            )


def create_container_config_from_permissions(
    plugin: LoadedPlugin,
) -> tuple[Any, Any] | None:
    """Create container and network configurations from plugin permissions.

    Returns None if the plugin does not have container_enabled set.

    Args:
        plugin: Loaded plugin with permissions

    Returns:
        Tuple of (ContainerConfig, NetworkPolicy) or None
    """
    if not plugin.manifest.permissions.container_enabled:
        return None

    from harombe.security.docker_manager import ContainerConfig, ResourceLimits
    from harombe.security.network import NetworkPolicy

    perms = plugin.manifest.permissions
    resource_limits_data = perms.resource_limits or {}

    resource_limits = ResourceLimits.from_mb(
        memory_mb=resource_limits_data.get("memory_mb", 256),
        cpu_cores=resource_limits_data.get("cpu_cores", 0.5),
        pids_limit=resource_limits_data.get("pids_limit", 50),
    )

    container_config = ContainerConfig(
        name=f"harombe-plugin-{plugin.manifest.name}",
        image=plugin.manifest.base_image,
        port=3100,  # Will be overridden by PluginContainerManager
        resource_limits=resource_limits,
    )

    network_policy = NetworkPolicy(
        allowed_domains=perms.network_domains,
        block_by_default=True,
    )

    return container_config, network_policy
