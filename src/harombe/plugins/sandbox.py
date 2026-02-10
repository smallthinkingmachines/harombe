"""Plugin permission enforcement (v1: declarative).

V1 is primarily declarative — sets the `dangerous` flag on tools
and integrates with HITL rules. Runtime network/filesystem enforcement
is planned for V2.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from harombe.tools.registry import _TOOLS

if TYPE_CHECKING:
    from harombe.plugins.manifest import LoadedPlugin

logger = logging.getLogger(__name__)


def apply_plugin_permissions(plugin: LoadedPlugin) -> None:
    """Apply declared permissions to a plugin's tools.

    For V1, this sets the `dangerous` flag on tools based on the
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
