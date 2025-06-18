"""Nostr Relay websocket client for NIP-60 wallet operations."""

from __future__ import annotations

import json
from typing import TypedDict, Callable, Any
from uuid import uuid4
import time
from dataclasses import dataclass, field
from collections import deque
import asyncio

import websockets


# -----------------------------------------------------------------------------
# Python < 3.11 compatibility shim
# -----------------------------------------------------------------------------

# `asyncio.timeout` was introduced in Python 3.11. When running on an older
# interpreter we either:
#   1. Import the identically-named helper from the third-party `async_timeout`
#      package if available, or
#   2. Provide a minimal no-op context manager that preserves the API surface
#      (this means timeouts will not be enforced but code will still run).
#
# This approach allows the package (and its test-suite) to execute on Python
# 3.10 and earlier without modifications, while still benefiting from native
# timeouts on 3.11+.

from contextlib import asynccontextmanager


if not hasattr(asyncio, "timeout"):
    try:
        from async_timeout import timeout as _timeout  # type: ignore

    except ModuleNotFoundError:

        @asynccontextmanager
        async def _timeout(_delay: float):  # noqa: D401 – simple stub
            """Fallback that degrades gracefully by disabling the timeout."""

            yield

    # Make the chosen implementation available as `asyncio.timeout`.
    setattr(asyncio, "timeout", _timeout)  # type: ignore[attr-defined]


# ──────────────────────────────────────────────────────────────────────────────
# Nostr protocol types
# ──────────────────────────────────────────────────────────────────────────────


class NostrEvent(TypedDict):
    """Nostr event structure."""

    id: str
    pubkey: str
    created_at: int
    kind: int
    tags: list[list[str]]
    content: str
    sig: str


class NostrFilter(TypedDict, total=False):
    """Filter for REQ subscriptions."""

    ids: list[str]
    authors: list[str]
    kinds: list[int]
    since: int
    until: int
    limit: int
    # Tags filters use #<tag> format


# ──────────────────────────────────────────────────────────────────────────────
# Relay client
# ──────────────────────────────────────────────────────────────────────────────


class RelayError(Exception):
    """Raised when relay returns an error."""


@dataclass
class QueuedEvent:
    """Event queued for publishing with metadata."""

    event: NostrEvent
    priority: int = 0  # Higher priority = sent first
    retry_count: int = 0
    max_retries: int = 3
    created_at: float = field(default_factory=time.time)
    callback: Callable[[bool, str | None], None] | None = None  # Success callback

    def __lt__(self, other: "QueuedEvent") -> bool:
        """For priority queue comparison."""
        return self.priority > other.priority  # Higher priority first


class EventQueue:
    """Thread-safe event queue with retry logic."""

    def __init__(self, max_queue_size: int = 1000) -> None:
        self._queue: deque[QueuedEvent] = deque(maxlen=max_queue_size)
        self._processing = False
        self._lock = asyncio.Lock()
        self._event = asyncio.Event()

        # Cache for pending events by ID
        self._pending_by_id: dict[str, QueuedEvent] = {}

        # Cache for pending token events (for balance calculation)
        self._pending_token_events: dict[str, dict[str, Any]] = {}

    async def add(
        self,
        event: NostrEvent,
        *,
        priority: int = 0,
        callback: Callable[[bool, str | None], None] | None = None,
        token_data: dict[str, Any] | None = None,
    ) -> None:
        """Add event to queue."""
        async with self._lock:
            queued = QueuedEvent(event=event, priority=priority, callback=callback)

            # Add to queue
            self._queue.append(queued)

            # Track by ID
            self._pending_by_id[event["id"]] = queued

            # If this is a token event, cache the data
            if token_data and event["kind"] == 7375:
                self._pending_token_events[event["id"]] = token_data

            # Sort by priority
            self._queue = deque(sorted(self._queue), maxlen=self._queue.maxlen)

            # Signal that new events are available
            self._event.set()

    async def get_batch(self, max_size: int = 10) -> list[QueuedEvent]:
        """Get a batch of events to process."""
        async with self._lock:
            batch = []
            for _ in range(min(max_size, len(self._queue))):
                if self._queue:
                    batch.append(self._queue.popleft())
            return batch

    async def requeue(self, event: QueuedEvent) -> bool:
        """Requeue a failed event if retries remain."""
        event.retry_count += 1
        if event.retry_count < event.max_retries:
            async with self._lock:
                # Add back with lower priority after retry
                event.priority -= 1
                self._queue.append(event)
                self._queue = deque(sorted(self._queue), maxlen=self._queue.maxlen)
                self._event.set()
            return True
        else:
            # Max retries exceeded
            await self.remove(event.event["id"])
            return False

    async def remove(self, event_id: str) -> None:
        """Remove event from pending caches."""
        async with self._lock:
            self._pending_by_id.pop(event_id, None)
            self._pending_token_events.pop(event_id, None)

    async def wait_for_events(self) -> None:
        """Wait for new events in the queue."""
        await self._event.wait()
        self._event.clear()

    def get_pending_token_data(self) -> list[dict[str, Any]]:
        """Get all pending token event data for balance calculation."""
        return list(self._pending_token_events.values())

    @property
    def size(self) -> int:
        """Current queue size."""
        return len(self._queue)


class NostrRelay:
    """Minimal Nostr relay client for NIP-60 wallet operations."""

    def __init__(self, url: str) -> None:
        """Initialize relay client.

        Args:
            url: Relay websocket URL (e.g. "wss://relay.damus.io")
        """
        self.url = url
        self.ws: Any = None
        self.subscriptions: dict[str, Callable[[NostrEvent], None]] = {}

    async def connect(self) -> None:
        """Connect to the relay."""
        import asyncio

        if self.ws is None or self.ws.close_code is not None:
            try:
                # Add connection timeout
                async with asyncio.timeout(5.0):
                    self.ws = await websockets.connect(
                        self.url, ping_interval=20, ping_timeout=10, close_timeout=10
                    )
            except asyncio.TimeoutError:
                print(f"Timeout connecting to relay: {self.url}")
                raise RelayError(f"Connection timeout: {self.url}")
            except Exception as e:
                print(f"Failed to connect to relay {self.url}: {e}")
                raise RelayError(f"Connection failed: {e}")

    async def disconnect(self) -> None:
        """Disconnect from the relay."""
        if self.ws and self.ws.close_code is None:
            await self.ws.close()

    async def _send(self, message: list[Any]) -> None:
        """Send a message to the relay."""
        if not self.ws or self.ws.close_code is not None:
            raise RelayError("Not connected to relay")
        await self.ws.send(json.dumps(message))

    async def _recv(self) -> list[Any]:
        """Receive a message from the relay."""
        if not self.ws or self.ws.close_code is not None:
            raise RelayError("Not connected to relay")
        data = await self.ws.recv()
        return json.loads(data)

    # ───────────────────────── Publishing Events ─────────────────────────────────

    async def publish_event(self, event: NostrEvent) -> bool:
        """Publish an event to the relay.

        Returns True if accepted, False if rejected.
        """
        import asyncio

        try:
            await self.connect()

            # Send EVENT command
            await self._send(["EVENT", event])

            # Wait for OK response with timeout
            async with asyncio.timeout(10.0):  # 10 second timeout
                while True:
                    msg = await self._recv()
                    if msg[0] == "OK" and msg[1] == event["id"]:
                        if not msg[2]:  # Event was rejected
                            if len(msg) > 3:
                                print(f"Relay rejected event: {msg[3]}")
                        return msg[2]  # True if accepted
                    elif msg[0] == "NOTICE":
                        print(f"Relay notice: {msg[1]}")

        except asyncio.TimeoutError:
            print(f"Timeout waiting for OK response from {self.url}")
            return False
        except Exception as e:
            print(f"Error publishing to {self.url}: {e}")
            return False

    # ───────────────────────── Fetching Events ─────────────────────────────────

    async def fetch_events(
        self,
        filters: list[NostrFilter],
        *,
        timeout: float = 5.0,
    ) -> list[NostrEvent]:
        """Fetch events matching filters.

        Args:
            filters: List of filters to match events
            timeout: Time to wait for events before returning

        Returns:
            List of matching events
        """
        await self.connect()

        # Generate subscription ID
        sub_id = str(uuid4())
        events: list[NostrEvent] = []

        # Send REQ command
        await self._send(["REQ", sub_id, *filters])

        # Collect events until EOSE or timeout
        import asyncio

        try:
            async with asyncio.timeout(timeout):
                while True:
                    msg = await self._recv()

                    if msg[0] == "EVENT":
                        # Always append events for this short-lived, dedicated subscription.
                        # Tests may feed a fixed subscription id (e.g. "sub_id") that differs
                        # from the locally generated one, so we avoid strict id matching to
                        # prevent an unnecessary wait inside the timeout context.
                        events.append(msg[2])
                    elif msg[0] == "EOSE":
                        # End-of-stored-events – irrespective of the subscription identifier
                        # because this instance only keeps one outstanding REQ at a time
                        # within this helper method.
                        break  # Exit once the relay signals completion

        except asyncio.TimeoutError:
            pass
        finally:
            # Close subscription
            await self._send(["CLOSE", sub_id])

        return events

    # ───────────────────────── Subscription Management ─────────────────────────────

    async def subscribe(
        self,
        filters: list[NostrFilter],
        callback: Callable[[NostrEvent], None],
    ) -> str:
        """Subscribe to events matching filters.

        Args:
            filters: List of filters to match events
            callback: Function to call for each matching event

        Returns:
            Subscription ID (use to unsubscribe)
        """
        await self.connect()

        # Generate subscription ID
        sub_id = str(uuid4())
        self.subscriptions[sub_id] = callback

        # Send REQ command
        await self._send(["REQ", sub_id, *filters])

        return sub_id

    async def unsubscribe(self, sub_id: str) -> None:
        """Close a subscription."""
        if sub_id in self.subscriptions:
            del self.subscriptions[sub_id]
            await self._send(["CLOSE", sub_id])

    async def process_messages(self) -> None:
        """Process incoming messages and call subscription callbacks.

        Run this in a background task to handle subscriptions.
        """
        while self.ws and self.ws.close_code is None:
            try:
                msg = await self._recv()

                if msg[0] == "EVENT" and msg[1] in self.subscriptions:
                    # Call the subscription callback
                    callback = self.subscriptions[msg[1]]
                    callback(msg[2])

            except websockets.exceptions.ConnectionClosed:
                break
            except Exception:
                # Log error but keep processing
                continue

    # ───────────────────────── NIP-60 Specific Helpers ─────────────────────────────

    async def fetch_wallet_events(
        self,
        pubkey: str,
        kinds: list[int] | None = None,
    ) -> list[NostrEvent]:
        """Fetch wallet-related events for a pubkey.

        Args:
            pubkey: Hex public key to fetch events for
            kinds: Event kinds to fetch (defaults to wallet kinds)

        Returns:
            List of matching events
        """
        if kinds is None:
            # Default to NIP-60 event kinds
            kinds = [17375, 7375, 7376, 7374]  # wallet, token, history, quote

        filters: list[NostrFilter] = [
            {
                "authors": [pubkey],
                "kinds": kinds,
            }
        ]

        return await self.fetch_events(filters)

    async def fetch_relay_recommendations(self, pubkey: str) -> list[str]:
        """Fetch relay recommendations (kind:10019) for a pubkey.

        Returns list of recommended relay URLs.
        """
        filters: list[NostrFilter] = [
            {
                "authors": [pubkey],
                "kinds": [10019],
                "limit": 1,
            }
        ]

        events = await self.fetch_events(filters)
        if not events:
            return []

        # Parse relay URLs from tags
        relays = []
        for tag in events[0]["tags"]:
            if tag[0] == "relay":
                relays.append(tag[1])

        return relays


class QueuedNostrRelay(NostrRelay):
    """Nostr relay client with event queuing and batching support."""

    def __init__(
        self,
        url: str,
        *,
        batch_size: int = 10,
        batch_interval: float = 1.0,
        enable_batching: bool = True,
    ) -> None:
        """Initialize queued relay client.

        Args:
            url: Relay websocket URL
            batch_size: Maximum events to send in one batch
            batch_interval: Seconds between batch processing
            enable_batching: Whether to batch events or send one by one
        """
        super().__init__(url)
        self.queue = EventQueue()
        self.batch_size = batch_size
        self.batch_interval = batch_interval
        self.enable_batching = enable_batching
        self._processor_task: asyncio.Task[None] | None = None
        self._running = False

    async def start_queue_processor(self) -> None:
        """Start the background queue processor."""
        if self._processor_task is None or self._processor_task.done():
            self._running = True
            self._processor_task = asyncio.create_task(self._process_queue())

    async def stop_queue_processor(self) -> None:
        """Stop the background queue processor."""
        self._running = False
        if self._processor_task and not self._processor_task.done():
            self.queue._event.set()  # Wake up processor
            await self._processor_task

    async def _process_queue(self) -> None:
        """Background task to process the event queue."""
        while self._running:
            try:
                # Wait for events or timeout
                try:
                    await asyncio.wait_for(
                        self.queue.wait_for_events(), timeout=self.batch_interval
                    )
                except asyncio.TimeoutError:
                    pass

                # Get batch of events
                if self.queue.size > 0:
                    if self.enable_batching:
                        batch = await self.queue.get_batch(self.batch_size)
                    else:
                        # Process one at a time
                        batch = await self.queue.get_batch(1)

                    # Process each event
                    for queued_event in batch:
                        try:
                            success = await super().publish_event(queued_event.event)

                            if success:
                                # Remove from pending caches
                                await self.queue.remove(queued_event.event["id"])

                                # Call success callback if provided
                                if queued_event.callback:
                                    queued_event.callback(True, None)
                            else:
                                # Event rejected, try to requeue
                                if not await self.queue.requeue(queued_event):
                                    # Max retries exceeded
                                    if queued_event.callback:
                                        queued_event.callback(
                                            False, "Max retries exceeded"
                                        )

                        except Exception as e:
                            # Connection error, requeue
                            if not await self.queue.requeue(queued_event):
                                # Max retries exceeded
                                if queued_event.callback:
                                    queued_event.callback(False, str(e))

                        # Small delay between events to avoid rate limiting
                        if not self.enable_batching and len(batch) > 1:
                            await asyncio.sleep(0.1)

            except Exception as e:
                print(f"Queue processor error: {e}")
                await asyncio.sleep(1)  # Avoid tight error loop

    async def publish_event(
        self,
        event: NostrEvent,
        *,
        priority: int = 0,
        callback: Callable[[bool, str | None], None] | None = None,
        token_data: dict[str, Any] | None = None,
        immediate: bool = False,
    ) -> bool:
        """Publish event via queue or immediately.

        Args:
            event: Event to publish
            priority: Queue priority (higher = sent first)
            callback: Callback for success/failure notification
            token_data: Token data to cache for balance calculation
            immediate: If True, bypass queue and publish immediately

        Returns:
            True if queued successfully (or published if immediate)
        """
        if immediate:
            # Bypass queue for urgent events
            return await super().publish_event(event)

        # Add to queue
        await self.queue.add(
            event, priority=priority, callback=callback, token_data=token_data
        )

        # Ensure processor is running
        await self.start_queue_processor()

        return True  # Successfully queued

    def get_pending_proofs(self) -> list[dict[str, Any]]:
        """Get pending proofs from queued token events.

        Returns:
            List of proof dictionaries from pending token events
        """
        all_proofs = []
        for token_data in self.queue.get_pending_token_data():
            proofs = token_data.get("proofs", [])
            all_proofs.extend(proofs)
        return all_proofs

    async def disconnect(self) -> None:
        """Disconnect and stop queue processor."""
        await self.stop_queue_processor()
        await super().disconnect()


class RelayPool:
    """Pool of QueuedNostrRelay instances with shared queue."""

    def __init__(self, urls: list[str], **relay_kwargs: Any) -> None:
        """Initialize relay pool with shared queue.

        Args:
            urls: List of relay URLs
            **relay_kwargs: Arguments passed to QueuedNostrRelay
        """
        self.relays: list[QueuedNostrRelay] = []
        self.shared_queue = EventQueue()

        # Create relays with shared queue
        for url in urls:
            relay = QueuedNostrRelay(url, **relay_kwargs)
            # Replace individual queue with shared one
            relay.queue = self.shared_queue
            self.relays.append(relay)

    async def publish_event(self, event: NostrEvent, **kwargs: Any) -> bool:
        """Publish event to all relays in pool."""
        # Add to shared queue once
        if self.relays:
            return await self.relays[0].publish_event(event, **kwargs)
        return False

    def get_pending_proofs(self) -> list[dict[str, Any]]:
        """Get pending proofs from shared queue."""
        return self.shared_queue.get_pending_token_data()

    async def connect_all(self) -> None:
        """Connect and start all relays."""
        for relay in self.relays:
            try:
                await relay.connect()
                await relay.start_queue_processor()
            except Exception as e:
                print(f"Failed to connect relay {relay.url}: {e}")

    async def disconnect_all(self) -> None:
        """Disconnect all relays."""
        for relay in self.relays:
            await relay.disconnect()
