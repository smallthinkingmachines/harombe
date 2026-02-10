"""Tests for channel base protocol and data models."""

from harombe.channels.base import ChannelAdapter, ChannelMessage


class TestChannelMessage:
    def test_create_basic(self):
        msg = ChannelMessage(text="hello", user_id="user1", channel_id="ch1")
        assert msg.text == "hello"
        assert msg.user_id == "user1"
        assert msg.channel_id == "ch1"
        assert msg.thread_id is None
        assert msg.metadata is None

    def test_create_with_thread(self):
        msg = ChannelMessage(
            text="reply",
            user_id="user1",
            channel_id="ch1",
            thread_id="thread-123",
        )
        assert msg.thread_id == "thread-123"

    def test_create_with_metadata(self):
        msg = ChannelMessage(
            text="hi",
            user_id="user1",
            channel_id="ch1",
            metadata={"source": "web"},
        )
        assert msg.metadata == {"source": "web"}

    def test_equality(self):
        msg1 = ChannelMessage(text="hi", user_id="u1", channel_id="c1")
        msg2 = ChannelMessage(text="hi", user_id="u1", channel_id="c1")
        assert msg1 == msg2


class TestChannelAdapterProtocol:
    def test_runtime_checkable(self):
        """ChannelAdapter is runtime_checkable, so we can use isinstance."""

        class MyAdapter:
            async def start(self) -> None: ...
            async def stop(self) -> None: ...
            async def send_message(
                self, channel_id: str, text: str, thread_id: str | None = None
            ) -> None: ...

        adapter = MyAdapter()
        assert isinstance(adapter, ChannelAdapter)

    def test_non_adapter_not_instance(self):
        """Objects missing required methods are not ChannelAdapter."""

        class NotAnAdapter:
            async def start(self) -> None: ...

            # Missing stop and send_message

        obj = NotAnAdapter()
        assert not isinstance(obj, ChannelAdapter)
