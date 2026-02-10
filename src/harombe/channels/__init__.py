"""Channel adapters for messaging integrations.

Each adapter receives messages from a channel, calls agent.run(),
and sends the response back. The agent, tools, and security stack are shared.
"""

from harombe.channels.base import ChannelAdapter, ChannelMessage

__all__ = ["ChannelAdapter", "ChannelMessage"]
