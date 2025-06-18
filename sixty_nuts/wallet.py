from __future__ import annotations

from enum import IntEnum
from typing import Literal, TypedDict, cast
import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass
import asyncio

import httpx
from coincurve import PrivateKey, PublicKey

from .mint import (
    Mint,
    ProofComplete as Proof,
    BlindedMessage,
    CurrencyUnit,
    PostMeltQuoteResponse,
)
from .relay import NostrRelay, NostrEvent, RelayError, QueuedNostrRelay, RelayPool
from .crypto import (
    unblind_signature,
    NIP44Encrypt,
    hash_to_curve,
    create_blinded_message,
)

try:
    from bech32 import bech32_decode, convertbits  # type: ignore
except ModuleNotFoundError:  # pragma: no cover – allow runtime miss
    bech32_decode = None  # type: ignore
    convertbits = None  # type: ignore

try:
    import cbor2
except ModuleNotFoundError:  # pragma: no cover – allow runtime miss
    cbor2 = None  # type: ignore


# ──────────────────────────────────────────────────────────────────────────────
# Protocol-level definitions
# ──────────────────────────────────────────────────────────────────────────────


class EventKind(IntEnum):
    """Nostr event kinds relevant to NIP-60."""

    RELAY_RECOMMENDATIONS = 10019
    Wallet = 17375  # wallet metadata
    Token = 7375  # unspent proofs
    History = 7376  # optional transaction log
    QuoteTracker = 7374  # mint quote tracker (optional)
    Delete = 5  # NIP-09 delete event


class ProofDict(TypedDict):
    """Extended proof structure for NIP-60 wallet use.

    Extends the basic Proof with mint URL tracking for multi-mint support.
    """

    id: str
    amount: int
    secret: str
    C: str
    mint: str | None  # Add mint URL tracking


@dataclass
class WalletState:
    """Current wallet state."""

    balance: int
    proofs: list[ProofDict]
    mint_keysets: dict[str, list[dict[str, str]]]  # mint_url -> keysets
    proof_to_event_id: dict[str, str] | None = (
        None  # proof_id -> event_id mapping (TODO)
    )


class WalletError(Exception):
    """Base class for wallet errors."""


# ──────────────────────────────────────────────────────────────────────────────
# Wallet implementation skeleton
# ──────────────────────────────────────────────────────────────────────────────


class Wallet:
    """Lightweight stateless Cashu wallet implementing NIP-60."""

    def __init__(
        self,
        nsec: str,  # nostr private key
        *,
        mint_urls: list[str] | None = None,  # cashu mint urls (can have multiple)
        currency: CurrencyUnit = "sat",  # Updated to use NUT-01 compliant type
        wallet_privkey: str | None = None,  # separate privkey for P2PK ecash (NIP-61)
        relays: list[str] | None = None,  # nostr relays to use
    ) -> None:
        self.nsec = nsec
        self._privkey = self._decode_nsec(nsec)
        self.mint_urls: list[str] = mint_urls or ["https://mint.minibits.cash/Bitcoin"]
        self.currency = currency
        # Validate currency unit is supported
        self._validate_currency_unit(currency)

        # Generate wallet privkey if not provided
        if wallet_privkey is None:
            wallet_privkey = self._generate_privkey()
        self.wallet_privkey = wallet_privkey
        self._wallet_privkey_obj = PrivateKey(bytes.fromhex(wallet_privkey))

        self.relays: list[str] = relays or [
            "wss://relay.damus.io",
            "wss://relay.nostr.band",
            "wss://relay.snort.social",
            "wss://nostr.mom",
        ]

        # Mint and relay instances
        self.mints: dict[str, Mint] = {}
        self.relay_instances: list[NostrRelay | QueuedNostrRelay] = []

        # Use RelayPool for queued event support
        self.relay_pool: RelayPool | None = None
        self._use_queued_relays = True  # Enable by default

        # Track minted quotes to prevent double-minting
        self._minted_quotes: set[str] = set()

        # Shared HTTP client reused by all Mint objects
        self.mint_client = httpx.AsyncClient()

        # Cache for proof validation results to prevent re-checking spent proofs
        self._proof_state_cache: dict[
            str, dict[str, str]
        ] = {}  # proof_id -> {state, timestamp}
        self._cache_expiry = 300  # 5 minutes

        # Track known spent proofs to avoid re-validation
        self._known_spent_proofs: set[str] = set()

        # Rate limiting for relay operations
        self._last_relay_operation = 0.0
        self._min_relay_interval = 1.0  # Minimum 1 second between operations

    def _validate_currency_unit(self, unit: CurrencyUnit) -> None:
        """Validate currency unit is supported per NUT-01.

        Args:
            unit: Currency unit to validate

        Raises:
            ValueError: If currency unit is not supported
        """
        # Type checking ensures unit is valid CurrencyUnit at compile time
        # This method can be extended for runtime validation if needed
        if unit not in [
            "btc",
            "sat",
            "msat",
            "usd",
            "eur",
            "gbp",
            "jpy",
            "auth",
            "usdt",
            "usdc",
            "dai",
        ]:
            raise ValueError(f"Unsupported currency unit: {unit}")

    # ───────────────────────── Crypto Helpers ─────────────────────────────────

    def _get_denominations(self) -> list[int]:
        """Get the list of supported denominations in descending order.

        Returns denominations as powers of 2, supporting up to 16384 (2^14).
        """
        return [
            16384,
            8192,
            4096,
            2048,
            1024,
            512,
            256,
            128,
            64,
            32,
            16,
            8,
            4,
            2,
            1,
        ]

    def _create_blinded_messages_for_amount(
        self, amount: int, keyset_id: str, *, prefer_large_denominations: bool = False
    ) -> tuple[list[BlindedMessage], list[str], list[str]]:
        """Create blinded messages for a given amount using optimal denominations.

        Args:
            amount: Total amount to split into denominations
            keyset_id: The keyset ID to use for the blinded messages
            prefer_large_denominations: If True, prefer fewer larger denominations

        Returns:
            Tuple of (blinded_messages, secrets, blinding_factors)
        """
        outputs: list[BlindedMessage] = []
        secrets: list[str] = []
        blinding_factors: list[str] = []

        remaining = amount

        if prefer_large_denominations:
            # Use larger denominations more aggressively for consolidation
            denominations = self._get_denominations()
            for denom in denominations:
                # Use as many of this denomination as possible
                count = remaining // denom
                for _ in range(count):
                    secret, r_hex, blinded_msg = self._create_blinded_message(
                        denom, keyset_id
                    )
                    outputs.append(blinded_msg)
                    secrets.append(secret)
                    blinding_factors.append(r_hex)
                    remaining -= denom
        else:
            # Standard denomination split (preserves privacy better)
            for denom in self._get_denominations():
                while remaining >= denom:
                    secret, r_hex, blinded_msg = self._create_blinded_message(
                        denom, keyset_id
                    )
                    outputs.append(blinded_msg)
                    secrets.append(secret)
                    blinding_factors.append(r_hex)
                    remaining -= denom

        return outputs, secrets, blinding_factors

    def _create_blinded_message(
        self, amount: int, keyset_id: str
    ) -> tuple[str, str, BlindedMessage]:
        """Create a properly blinded message for the mint using the updated crypto API.

        Returns:
            Tuple of (secret_base64, blinding_factor_hex, blinded_message)
        """
        # Generate random 32-byte secret
        secret_bytes = secrets.token_bytes(32)

        # Convert to hex string (this is what Cashu protocol expects)
        secret_hex = secret_bytes.hex()

        # For blinding, use UTF-8 bytes of the hex string (Cashu standard)
        secret_utf8_bytes = secret_hex.encode("utf-8")

        # Use the new create_blinded_message function
        blinded_msg, blinding_data = create_blinded_message(
            amount=amount, keyset_id=keyset_id, secret=secret_utf8_bytes
        )

        # For NIP-60 storage, convert to base64
        secret_base64 = base64.b64encode(secret_bytes).decode("ascii")

        # Extract the blinding factor - it's already a hex string in BlindingData
        blinding_factor_hex = blinding_data.r

        return secret_base64, blinding_factor_hex, blinded_msg

    def _get_mint_pubkey_for_amount(
        self, keys_data: dict[str, str], amount: int
    ) -> PublicKey | None:
        """Get the mint's public key for a specific amount.

        Args:
            keys_data: Dictionary mapping amounts to public keys
            amount: The denomination amount

        Returns:
            PublicKey or None if not found
        """
        # Keys are indexed by string amount
        pubkey_hex = keys_data.get(str(amount))
        if pubkey_hex:
            return PublicKey(bytes.fromhex(pubkey_hex))
        return None

    def _decode_nsec(self, nsec: str) -> PrivateKey:
        """Decode `nsec` (bech32 as per Nostr) or raw hex private key."""
        if nsec.startswith("nsec1"):
            if bech32_decode is None or convertbits is None:
                raise NotImplementedError(
                    "bech32 library missing – install `bech32` to use bech32-encoded nsec keys"
                )

            hrp, data = bech32_decode(nsec)
            if hrp != "nsec" or data is None:
                raise ValueError("Malformed nsec bech32 string")

            decoded = bytes(convertbits(data, 5, 8, False))  # type: ignore
            if len(decoded) != 32:
                raise ValueError("Invalid nsec length after decoding")
            return PrivateKey(decoded)

        # Fallback – treat as raw hex key
        return PrivateKey(bytes.fromhex(nsec))

    def _generate_privkey(self) -> str:
        """Generate a new secp256k1 private key for wallet P2PK operations."""
        return PrivateKey().to_hex()

    def _get_pubkey(self, privkey: PrivateKey | None = None) -> str:
        """Get hex public key from private key (defaults to main nsec)."""
        effective_privkey = privkey if privkey is not None else self._privkey
        # Nostr uses x-only public keys (32 bytes, without the prefix byte)
        compressed_pubkey = effective_privkey.public_key.format(compressed=True)
        x_only_pubkey = compressed_pubkey[1:]  # Remove the prefix byte
        return x_only_pubkey.hex()

    def _get_pubkey_compressed(self, privkey: PrivateKey | None = None) -> str:
        """Get full compressed hex public key for encryption (33 bytes)."""
        effective_privkey = privkey if privkey is not None else self._privkey
        return effective_privkey.public_key.format(compressed=True).hex()

    def _sign_event(self, event: dict) -> dict:
        """Sign a Nostr event with the user's private key."""
        # Ensure event has required fields
        event["pubkey"] = self._get_pubkey()
        event["created_at"] = event.get("created_at", int(time.time()))
        event["id"] = self._compute_event_id(event)

        # Sign the event
        sig = self._privkey.sign_schnorr(bytes.fromhex(event["id"]))
        event["sig"] = sig.hex()

        return event

    def _compute_event_id(self, event: dict) -> str:
        """Compute Nostr event ID (hash of canonical JSON)."""
        # Canonical format: [0, pubkey, created_at, kind, tags, content]
        canonical = json.dumps(
            [
                0,
                event["pubkey"],
                event["created_at"],
                event["kind"],
                event["tags"],
                event["content"],
            ],
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return hashlib.sha256(canonical.encode()).hexdigest()

    # ───────────────────────── NIP-44 Encryption ─────────────────────────────────

    def _nip44_encrypt(
        self, plaintext: str, recipient_pubkey: str | None = None
    ) -> str:
        """Encrypt content using NIP-44 v2."""
        if recipient_pubkey is None:
            recipient_pubkey = self._get_pubkey_compressed()

        return NIP44Encrypt.encrypt(plaintext, self._privkey, recipient_pubkey)

    def _nip44_decrypt(self, ciphertext: str, sender_pubkey: str | None = None) -> str:
        """Decrypt content using NIP-44 v2."""
        if sender_pubkey is None:
            sender_pubkey = self._get_pubkey_compressed()

        return NIP44Encrypt.decrypt(ciphertext, self._privkey, sender_pubkey)

    def _create_event(
        self,
        kind: int,
        content: str = "",
        tags: list[list[str]] | None = None,
    ) -> dict:
        """Create unsigned Nostr event structure."""
        return {
            "kind": kind,
            "content": content,
            "tags": tags or [],
            "created_at": int(time.time()),
        }

    # ───────────────────────── Helper Methods ─────────────────────────────────

    def _get_mint(self, mint_url: str) -> Mint:
        """Get or create mint instance for URL."""
        if mint_url not in self.mints:
            self.mints[mint_url] = Mint(mint_url, client=self.mint_client)
        return self.mints[mint_url]

    async def _get_relay_connections(self) -> list[NostrRelay]:
        """Get relay connections, discovering if needed."""
        if self._use_queued_relays and self.relay_pool is None:
            # Try to discover relays
            discovered_relays = await self._discover_relays()
            relay_urls = discovered_relays or self.relays

            # Create relay pool with queued support
            self.relay_pool = RelayPool(
                relay_urls[:5],  # Use up to 5 relays
                batch_size=10,
                batch_interval=0.5,  # Process queue every 0.5 seconds
                enable_batching=True,
            )

            # Connect all relays in pool
            await self.relay_pool.connect_all()

            # For compatibility, add relays to instances list
            self.relay_instances = cast(
                list[NostrRelay | QueuedNostrRelay], self.relay_pool.relays
            )

        elif not self._use_queued_relays and not self.relay_instances:
            # Legacy mode: use regular relays without queuing
            discovered_relays = await self._discover_relays()
            relay_urls = discovered_relays or self.relays

            # Try to connect to relays
            for url in relay_urls[:5]:  # Try up to 5 relays
                try:
                    relay = NostrRelay(url)
                    await relay.connect()
                    self.relay_instances.append(relay)

                    # Stop after successfully connecting to 3 relays
                    if len(self.relay_instances) >= 3:
                        break
                except Exception:
                    continue

            if not self.relay_instances:
                raise RelayError("Could not connect to any relay")

        return self.relay_instances

    async def _discover_relays(self) -> list[str]:
        """Discover relays from kind:10019 events."""
        # Use a well-known relay to bootstrap
        bootstrap_relay = NostrRelay("wss://relay.damus.io")
        try:
            await bootstrap_relay.connect()
            relays = await bootstrap_relay.fetch_relay_recommendations(
                self._get_pubkey()
            )
            return relays
        except Exception:
            return []
        finally:
            await bootstrap_relay.disconnect()

    async def _rate_limit_relay_operations(self) -> None:
        """Apply rate limiting to relay operations."""
        now = time.time()
        time_since_last = now - self._last_relay_operation
        if time_since_last < self._min_relay_interval:
            await asyncio.sleep(self._min_relay_interval - time_since_last)
        self._last_relay_operation = time.time()

    def _estimate_event_size(self, event: dict) -> int:
        """Estimate the size of an event in bytes."""
        return len(json.dumps(event, separators=(",", ":")))

    async def _publish_to_relays(
        self,
        event: dict,
        *,
        token_data: dict[str, object] | None = None,
        priority: int = 0,
    ) -> str:
        """Publish event to all relays and return event ID."""
        # Apply rate limiting
        await self._rate_limit_relay_operations()

        # Use relay pool if available for queued publishing
        if self._use_queued_relays and self.relay_pool:
            event_dict = NostrEvent(**event)  # type: ignore

            # Determine priority based on event kind
            if event["kind"] == EventKind.Token:
                priority = 10  # High priority for token events
            elif event["kind"] == EventKind.History:
                priority = 5  # Medium priority for history
            else:
                priority = priority or 0

            # Add to queue with token data if provided
            success = await self.relay_pool.publish_event(
                event_dict,
                priority=priority,
                token_data=token_data,
                immediate=False,  # Use queue
            )

            if success:
                return event["id"]
            else:
                raise RelayError("Failed to queue event for publishing")

        # Legacy mode: direct publishing
        relays = await self._get_relay_connections()
        event_dict = NostrEvent(**event)  # type: ignore

        # Try to publish to at least one relay
        published = False
        errors = []

        for relay in relays:
            try:
                if await relay.publish_event(event_dict):
                    published = True
                else:
                    errors.append(f"{relay.url}: Event rejected")
            except Exception as e:
                errors.append(f"{relay.url}: {str(e)}")
                continue

        if not published:
            # Only log if we can't publish anywhere to avoid log spam
            error_msg = f"Failed to publish event to any relay. Last error: {errors[-1] if errors else 'Unknown'}"
            print(f"Warning: {error_msg}")
            # Don't raise exception - allow operations to continue
            return event["id"]

        return event["id"]

    def _serialize_proofs_for_token(
        self, proofs: list[ProofDict], mint_url: str
    ) -> str:
        """Serialize proofs into a Cashu token format."""
        # Convert ProofDict (with base64 secrets) to format expected by Cashu tokens (hex secrets)
        token_proofs = []
        for proof in proofs:
            # Convert base64 secret to hex for Cashu token
            try:
                secret_bytes = base64.b64decode(proof["secret"])
                secret_hex = secret_bytes.hex()
            except Exception:
                # Fallback: assume it's already hex
                secret_hex = proof["secret"]

            token_proofs.append(
                {
                    "id": proof["id"],
                    "amount": proof["amount"],
                    "secret": secret_hex,  # Cashu tokens expect hex
                    "C": proof["C"],
                }
            )

        # Cashu token format: cashuA<base64url(json)>
        token_data = {
            "token": [{"mint": mint_url, "proofs": token_proofs}],
            "unit": self.currency
            or "sat",  # Ensure unit is always present, default to "sat"
            "memo": "NIP-60 wallet transfer",  # Default memo, but could be passed as arg
        }
        json_str = json.dumps(token_data, separators=(",", ":"))
        encoded = base64.urlsafe_b64encode(json_str.encode()).decode().rstrip("=")
        return f"cashuA{encoded}"

    def _parse_cashu_token(
        self, token: str
    ) -> tuple[str, CurrencyUnit, list[ProofDict]]:
        """Parse Cashu token and return (mint_url, unit, proofs)."""
        if not token.startswith("cashu"):
            raise ValueError("Invalid token format")

        # Check token version
        if token.startswith("cashuA"):
            # Version 3 - JSON format
            encoded = token[6:]  # Remove "cashuA"
            # Add correct padding – (-len) % 4 equals 0,1,2,3
            encoded += "=" * ((-len(encoded)) % 4)

            decoded = base64.urlsafe_b64decode(encoded).decode()
            token_data = json.loads(decoded)

            # Extract mint and proofs from JSON format
            mint_info = token_data["token"][0]
            # Safely get unit, defaulting to "sat" if not present (as per Cashu V3 common practice)
            unit_str = token_data.get("unit", "sat")
            # Cast to CurrencyUnit - validate it's a known unit
            token_unit: CurrencyUnit = cast(CurrencyUnit, unit_str)
            token_proofs = mint_info["proofs"]

            # Convert hex secrets to base64 for NIP-60 storage
            nip60_proofs: list[ProofDict] = []
            for proof in token_proofs:
                # Convert hex secret to base64
                try:
                    secret_bytes = bytes.fromhex(proof["secret"])
                    secret_base64 = base64.b64encode(secret_bytes).decode("ascii")
                except Exception:
                    # Fallback: assume it's already base64
                    secret_base64 = proof["secret"]

                nip60_proofs.append(
                    ProofDict(
                        id=proof["id"],
                        amount=proof["amount"],
                        secret=secret_base64,  # Store as base64 for NIP-60
                        C=proof["C"],
                        mint=mint_info["mint"],
                    )
                )

            return mint_info["mint"], token_unit, nip60_proofs

        elif token.startswith("cashuB"):
            # Version 4 - CBOR format
            if cbor2 is None:
                raise ImportError("cbor2 library required for cashuB tokens")

            encoded = token[6:]  # Remove "cashuB"
            # Add padding for base64
            encoded += "=" * ((-len(encoded)) % 4)

            decoded_bytes = base64.urlsafe_b64decode(encoded)
            token_data = cbor2.loads(decoded_bytes)

            # Extract from CBOR format - different structure
            # 'm' = mint URL, 'u' = unit, 't' = tokens array
            mint_url = token_data["m"]
            unit_str = token_data["u"]
            # Cast to CurrencyUnit
            cbor_unit: CurrencyUnit = cast(CurrencyUnit, unit_str)
            proofs = []

            # Each token in 't' has 'i' (keyset id) and 'p' (proofs)
            for token_entry in token_data["t"]:
                keyset_id = token_entry["i"].hex()  # Convert bytes to hex
                for proof in token_entry["p"]:
                    # CBOR format already has hex secret, convert to base64
                    secret_hex = proof["s"]
                    try:
                        secret_bytes = bytes.fromhex(secret_hex)
                        secret_base64 = base64.b64encode(secret_bytes).decode("ascii")
                    except Exception:
                        # Fallback
                        secret_base64 = secret_hex

                    # Convert CBOR proof format to our ProofDict format
                    proofs.append(
                        ProofDict(
                            id=keyset_id,
                            amount=proof["a"],
                            secret=secret_base64,  # Store as base64 for NIP-60
                            C=proof["c"].hex(),  # Convert bytes to hex
                            mint=mint_url,
                        )
                    )

            return mint_url, cbor_unit, proofs
        else:
            raise ValueError(f"Unknown token version: {token[:7]}")

    # ───────────────────────── Wallet State Management ─────────────────────────

    async def create_wallet_event(self) -> str:
        """Create or update the replaceable wallet event (kind 17375).

        Returns the published event id.
        """
        # Create content array with wallet metadata
        content_data = [
            ["privkey", self.wallet_privkey],
        ]
        for mint_url in self.mint_urls:
            content_data.append(["mint", mint_url])

        # Encrypt content
        content_json = json.dumps(content_data)
        encrypted_content = self._nip44_encrypt(content_json)

        # NIP-60 requires at least one mint tag in the tags array (unencrypted)
        # This is critical for wallet discovery!
        tags = [["mint", url] for url in self.mint_urls]

        # Create replaceable wallet event
        event = self._create_event(
            kind=EventKind.Wallet,
            content=encrypted_content,
            tags=tags,
        )

        # Sign and publish
        signed_event = self._sign_event(event)
        return await self._publish_to_relays(signed_event)

    def _compute_proof_y_values(self, proofs: list[ProofDict]) -> list[str]:
        """Compute Y values for proofs to use in check_state API.

        Args:
            proofs: List of proof dictionaries

        Returns:
            List of Y values (hex encoded compressed public keys)
        """
        y_values = []
        for proof in proofs:
            # NIP-60 stores secrets as base64
            secret_base64 = proof["secret"]
            try:
                # Decode base64 to get raw secret bytes
                secret_bytes = base64.b64decode(secret_base64)
                # Convert to hex string
                secret_hex = secret_bytes.hex()
            except Exception:
                # Fallback for hex-encoded secrets (backwards compatibility)
                secret_hex = proof["secret"]

            # Hash to curve point using UTF-8 bytes of hex string (Cashu standard)
            secret_utf8_bytes = secret_hex.encode("utf-8")
            Y = hash_to_curve(secret_utf8_bytes)
            # Convert to compressed hex format
            y_hex = Y.format(compressed=True).hex()
            y_values.append(y_hex)
        return y_values

    def _is_proof_state_cached(self, proof_id: str) -> tuple[bool, str | None]:
        """Check if proof state is cached and still valid."""
        if proof_id in self._proof_state_cache:
            cache_entry = self._proof_state_cache[proof_id]
            timestamp = float(cache_entry.get("timestamp", 0))
            if time.time() - timestamp < self._cache_expiry:
                return True, cache_entry.get("state")
        return False, None

    def _cache_proof_state(self, proof_id: str, state: str) -> None:
        """Cache proof state with timestamp."""
        self._proof_state_cache[proof_id] = {
            "state": state,
            "timestamp": str(time.time()),
        }

        # Track spent proofs separately for faster lookup
        if state == "SPENT":
            self._known_spent_proofs.add(proof_id)

    def clear_spent_proof_cache(self) -> None:
        """Clear the spent proof cache to prevent memory growth."""
        self._proof_state_cache.clear()
        self._known_spent_proofs.clear()

    async def _validate_proofs_with_cache(
        self, proofs: list[ProofDict]
    ) -> list[ProofDict]:
        """Validate proofs using cache to avoid re-checking spent proofs."""
        valid_proofs = []
        proofs_to_check: list[ProofDict] = []

        # First pass: check cache and filter out known spent proofs
        for proof in proofs:
            proof_id = f"{proof['secret']}:{proof['C']}"

            # Skip known spent proofs immediately
            if proof_id in self._known_spent_proofs:
                continue

            is_cached, cached_state = self._is_proof_state_cached(proof_id)
            if is_cached:
                if cached_state == "UNSPENT":
                    valid_proofs.append(proof)
                # SPENT proofs are filtered out (don't add to valid_proofs)
            else:
                proofs_to_check.append(proof)

        # Second pass: validate uncached proofs
        if proofs_to_check:
            # Group by mint for batch validation
            proofs_by_mint: dict[str, list[ProofDict]] = {}
            for proof in proofs_to_check:
                # Get mint URL from proof, fallback to first mint URL
                mint_url = proof.get("mint") or (
                    self.mint_urls[0] if self.mint_urls else None
                )
                if mint_url:
                    if mint_url not in proofs_by_mint:
                        proofs_by_mint[mint_url] = []
                    proofs_by_mint[mint_url].append(proof)

            # Validate with each mint
            for mint_url, mint_proofs in proofs_by_mint.items():
                try:
                    mint = self._get_mint(mint_url)
                    y_values = self._compute_proof_y_values(mint_proofs)
                    state_response = await mint.check_state(Ys=y_values)

                    for i, proof in enumerate(mint_proofs):
                        proof_id = f"{proof['secret']}:{proof['C']}"
                        if i < len(state_response["states"]):
                            state_info = state_response["states"][i]
                            state = state_info.get("state", "UNKNOWN")

                            # Cache the result
                            self._cache_proof_state(proof_id, state)

                            # Only include unspent proofs
                            if state == "UNSPENT":
                                valid_proofs.append(proof)

                        else:
                            # No state info - assume valid but don't cache
                            valid_proofs.append(proof)

                except Exception:
                    # If validation fails, include proofs but don't cache
                    valid_proofs.extend(mint_proofs)

        return valid_proofs

    async def fetch_wallet_state(self, *, check_proofs: bool = True) -> WalletState:
        """Fetch wallet, token events and compute balance.

        Args:
            check_proofs: If True, validate all proofs with mint before returning state
        """
        # Clear spent proof cache to ensure fresh validation
        if check_proofs:
            self.clear_spent_proof_cache()

        relays = await self._get_relay_connections()
        pubkey = self._get_pubkey()

        # Fetch all wallet-related events
        all_events: list[NostrEvent] = []
        event_ids_seen: set[str] = set()

        for relay in relays:
            try:
                events = await relay.fetch_wallet_events(pubkey)
                # Deduplicate events
                for event in events:
                    if event["id"] not in event_ids_seen:
                        all_events.append(event)
                        event_ids_seen.add(event["id"])
            except Exception:
                continue

        # Find wallet event
        wallet_event = None
        for event in all_events:
            if event["kind"] == EventKind.Wallet:
                wallet_event = event
                break

        # Parse wallet metadata
        if wallet_event:
            try:
                decrypted = self._nip44_decrypt(wallet_event["content"])
                wallet_data = json.loads(decrypted)

                # Update mint URLs from wallet event
                self.mint_urls = []
                for item in wallet_data:
                    if item[0] == "mint":
                        self.mint_urls.append(item[1])
                    elif item[0] == "privkey":
                        self.wallet_privkey = item[1]
            except Exception as e:
                # Skip wallet event if it can't be decrypted
                print(f"Warning: Could not decrypt wallet event: {e}")

        # Collect token events
        token_events = [e for e in all_events if e["kind"] == EventKind.Token]

        # Track deleted token events
        deleted_ids = set()
        for event in all_events:
            if event["kind"] == EventKind.Delete:
                for tag in event["tags"]:
                    if tag[0] == "e":
                        deleted_ids.add(tag[1])

        # Aggregate unspent proofs taking into account NIP-60 roll-overs and avoiding duplicates
        all_proofs: list[ProofDict] = []
        proof_to_event_id: dict[str, str] = {}

        # Index events newest → oldest so that when we encounter a replacement first we can ignore the ones it deletes later
        token_events_sorted = sorted(
            token_events, key=lambda e: e["created_at"], reverse=True
        )

        invalid_token_ids: set[str] = set(deleted_ids)
        proof_seen: set[str] = set()

        for event in token_events_sorted:
            if event["id"] in invalid_token_ids:
                continue

            try:
                decrypted = self._nip44_decrypt(event["content"])
                token_data = json.loads(decrypted)
            except Exception as e:
                # Skip this event if it can't be decrypted
                print(f"Warning: Could not decrypt token event {event['id']}: {e}")
                continue

            # Mark tokens referenced in the "del" field as superseded
            for old_id in token_data.get("del", []):
                invalid_token_ids.add(old_id)

            if event["id"] in invalid_token_ids:
                continue

            proofs = token_data.get("proofs", [])
            mint_url = token_data.get(
                "mint", self.mint_urls[0] if self.mint_urls else None
            )

            for proof in proofs:
                proof_id = f"{proof['secret']}:{proof['C']}"
                if proof_id in proof_seen:
                    continue
                proof_seen.add(proof_id)
                # Add mint URL to proof
                proof_with_mint: ProofDict = ProofDict(
                    id=proof["id"],
                    amount=proof["amount"],
                    secret=proof["secret"],
                    C=proof["C"],
                    mint=mint_url,
                )
                all_proofs.append(proof_with_mint)
                proof_to_event_id[proof_id] = event["id"]

        # Include pending proofs from relay pool queue
        if self._use_queued_relays and self.relay_pool:
            pending_token_data = self.relay_pool.get_pending_proofs()

            for token_data in pending_token_data:
                mint_url = token_data.get(
                    "mint", self.mint_urls[0] if self.mint_urls else None
                )
                proofs = token_data.get("proofs", [])

                for proof in proofs:
                    proof_id = f"{proof['secret']}:{proof['C']}"
                    if proof_id in proof_seen:
                        continue
                    proof_seen.add(proof_id)

                    # Mark pending proofs with a special event ID
                    pending_proof_with_mint: ProofDict = ProofDict(
                        id=proof["id"],
                        amount=proof["amount"],
                        secret=proof["secret"],
                        C=proof["C"],
                        mint=mint_url,
                    )
                    all_proofs.append(pending_proof_with_mint)
                    proof_to_event_id[proof_id] = "__pending__"  # Special marker

        # Validate proofs using cache system if requested
        if check_proofs and all_proofs:
            # Don't validate pending proofs (they haven't been published yet)
            non_pending_proofs = [
                p
                for p in all_proofs
                if proof_to_event_id.get(f"{p['secret']}:{p['C']}", "") != "__pending__"
            ]
            pending_proofs = [
                p
                for p in all_proofs
                if proof_to_event_id.get(f"{p['secret']}:{p['C']}", "") == "__pending__"
            ]

            # Validate only non-pending proofs
            validated_proofs = await self._validate_proofs_with_cache(
                non_pending_proofs
            )

            # Add back pending proofs (assume they're valid)
            all_proofs = validated_proofs + pending_proofs

        # Calculate balance
        balance = sum(p["amount"] for p in all_proofs)

        # Fetch mint keysets
        mint_keysets: dict[str, list[dict[str, str]]] = {}
        for mint_url in self.mint_urls:
            mint = self._get_mint(mint_url)
            try:
                keys_resp = await mint.get_keys()
                # Convert Keyset type to dict[str, str] for wallet state
                keysets_as_dicts: list[dict[str, str]] = []
                for keyset in keys_resp.get("keysets", []):
                    # Convert each keyset to a simple dict
                    keyset_dict: dict[str, str] = {
                        "id": keyset["id"],
                        "unit": keyset["unit"],
                    }
                    # Add keys if present
                    if "keys" in keyset and isinstance(keyset["keys"], dict):
                        keyset_dict.update(keyset["keys"])
                    keysets_as_dicts.append(keyset_dict)
                mint_keysets[mint_url] = keysets_as_dicts
            except Exception:
                mint_keysets[mint_url] = []

        return WalletState(
            balance=balance,
            proofs=all_proofs,
            mint_keysets=mint_keysets,
            proof_to_event_id=proof_to_event_id,
        )

    async def get_balance(self, *, check_proofs: bool = True) -> int:
        """Get current wallet balance.

        Args:
            check_proofs: If True, validate all proofs with mint before returning balance

        Returns:
            Current balance in the wallet's currency unit

        Example:
            balance = await wallet.get_balance()
            print(f"Balance: {balance} sats")
        """
        state = await self.fetch_wallet_state(check_proofs=check_proofs)
        return state.balance

    # ───────────────────────────── Token Events ───────────────────────────────

    async def _split_large_token_events(
        self,
        proofs: list[ProofDict],
        mint_url: str,
        deleted_token_ids: list[str] | None = None,
    ) -> list[str]:
        """Split large token events into smaller chunks to avoid relay size limits."""
        if not proofs:
            return []

        # Maximum event size (leaving buffer for encryption overhead)
        max_size = 60000  # 60KB limit with buffer
        event_ids: list[str] = []
        current_batch: list[ProofDict] = []

        for proof in proofs:
            # Test adding this proof to current batch
            test_batch = current_batch + [proof]

            # Create test event content
            content_data = {
                "mint": mint_url,
                "proofs": test_batch,
            }

            # Add del field only to first event
            if deleted_token_ids and not event_ids:
                content_data["del"] = deleted_token_ids

            content_json = json.dumps(content_data)
            encrypted_content = self._nip44_encrypt(content_json)

            test_event = self._create_event(
                kind=EventKind.Token,
                content=encrypted_content,
                tags=[],
            )

            # Check if this would exceed size limit
            if self._estimate_event_size(test_event) > max_size and current_batch:
                # Current batch is full, create event and start new batch
                final_content_data = {
                    "mint": mint_url,
                    "proofs": current_batch,
                }

                # Add del field only to first event
                if deleted_token_ids and not event_ids:
                    final_content_data["del"] = deleted_token_ids

                final_content_json = json.dumps(final_content_data)
                final_encrypted_content = self._nip44_encrypt(final_content_json)

                final_event = self._create_event(
                    kind=EventKind.Token,
                    content=final_encrypted_content,
                    tags=[],
                )

                signed_event = self._sign_event(final_event)
                event_id = await self._publish_to_relays(
                    signed_event,
                    token_data=cast(dict[str, object], final_content_data),
                    priority=10,
                )
                event_ids.append(event_id)
                current_batch = [proof]
            else:
                current_batch.append(proof)

        # Add final batch if not empty
        if current_batch:
            final_content_data = {
                "mint": mint_url,
                "proofs": current_batch,
            }

            # Add del field only to first event
            if deleted_token_ids and not event_ids:
                final_content_data["del"] = deleted_token_ids

            final_content_json = json.dumps(final_content_data)
            final_encrypted_content = self._nip44_encrypt(final_content_json)

            final_event = self._create_event(
                kind=EventKind.Token,
                content=final_encrypted_content,
                tags=[],
            )

            signed_event = self._sign_event(final_event)
            event_id = await self._publish_to_relays(
                signed_event,
                token_data=cast(dict[str, object], final_content_data),
                priority=10,
            )
            event_ids.append(event_id)

        return event_ids

    async def publish_token_event(
        self,
        proofs: list[ProofDict],
        *,
        deleted_token_ids: list[str] | None = None,
    ) -> str:
        """Publish encrypted token event (kind 7375) and return its id."""
        # First, delete old token events if specified
        if deleted_token_ids:
            for token_id in deleted_token_ids:
                await self.delete_token_event(token_id)

        # Get mint URL from proofs or use default
        if proofs and proofs[0].get("mint"):
            mint_url = proofs[0]["mint"]
        else:
            mint_url = self.mint_urls[0] if self.mint_urls else None

        if not mint_url:
            raise WalletError("No mint URL available for token event")

        # Check if we need to split the event due to size
        # Create a test event to estimate size
        content_data = {
            "mint": mint_url,
            "proofs": proofs,
        }

        if deleted_token_ids:
            content_data["del"] = deleted_token_ids

        content_json = json.dumps(content_data)
        encrypted_content = self._nip44_encrypt(content_json)

        test_event = self._create_event(
            kind=EventKind.Token,
            content=encrypted_content,
            tags=[],
        )

        # If event is too large, split it
        if self._estimate_event_size(test_event) > 60000:
            event_ids = await self._split_large_token_events(
                proofs, mint_url, deleted_token_ids
            )
            return event_ids[0] if event_ids else ""

        # Event is small enough, publish as single event
        signed_event = self._sign_event(test_event)

        # Pass token data to relay pool for pending balance tracking
        return await self._publish_to_relays(
            signed_event,
            token_data=cast(dict[str, object], content_data),
            priority=10,  # High priority for token events
        )

    async def delete_token_event(self, event_id: str) -> None:
        """Delete a token event via NIP-09 (kind 5)."""
        # Create delete event
        event = self._create_event(
            kind=EventKind.Delete,
            content="",
            tags=[
                ["e", event_id],
                ["k", str(EventKind.Token.value)],
            ],
        )

        # Sign and publish
        signed_event = self._sign_event(event)
        await self._publish_to_relays(signed_event)

    # ──────────────────────────── History Events ──────────────────────────────

    async def publish_spending_history(
        self,
        *,
        direction: Literal["in", "out"],
        amount: int,
        created_token_ids: list[str] | None = None,
        destroyed_token_ids: list[str] | None = None,
        redeemed_event_id: str | None = None,
    ) -> str:
        """Publish kind 7376 spending history event and return its id."""
        # Build encrypted content
        content_data = [
            ["direction", direction],
            ["amount", str(amount)],
        ]

        # Add e-tags for created tokens (encrypted)
        if created_token_ids:
            for token_id in created_token_ids:
                content_data.append(["e", token_id, "", "created"])

        # Add e-tags for destroyed tokens (encrypted)
        if destroyed_token_ids:
            for token_id in destroyed_token_ids:
                content_data.append(["e", token_id, "", "destroyed"])

        # Encrypt content
        content_json = json.dumps(content_data)
        encrypted_content = self._nip44_encrypt(content_json)

        # Build tags (redeemed tags stay unencrypted)
        tags = []
        if redeemed_event_id:
            tags.append(["e", redeemed_event_id, "", "redeemed"])

        # Create history event
        event = self._create_event(
            kind=EventKind.History,
            content=encrypted_content,
            tags=tags,
        )

        # Sign and publish
        signed_event = self._sign_event(event)
        return await self._publish_to_relays(signed_event)

    # ─────────────────────────────── Receive ──────────────────────────────────

    async def redeem(self, token: str, *, auto_swap: bool = True) -> tuple[int, str]:
        """Redeem a Cashu token into the wallet balance.

        If the token is from an untrusted mint (not in wallet's mint_urls),
        it will automatically be swapped to the wallet's primary mint.

        Args:
            token: Cashu token to redeem
            auto_swap: If True, automatically swap tokens from untrusted mints

        Returns:
            Tuple of (amount, unit) added to wallet
        """
        # Parse token
        mint_url, unit, proofs = self._parse_cashu_token(token)

        # Check if this is a trusted mint
        if auto_swap and self.mint_urls and mint_url not in self.mint_urls:
            # Token is from untrusted mint - swap to our primary mint
            return await self.swap_mints(token, target_mint=self.mint_urls[0])

        # Proceed with normal redemption for trusted mints
        mint = self._get_mint(mint_url)

        # Convert to mint proof format
        mint_proofs: list[Proof] = []
        for p in proofs:
            mint_proofs.append(self._proofdict_to_mint_proof(p))

        # Create blinded messages for new proofs
        # In production, implement proper blinding
        total_amount = sum(p["amount"] for p in proofs)

        # Simple denomination split using mint's active keyset id
        keys_resp_active = await mint.get_keys()
        keysets_active = keys_resp_active.get("keysets", [])
        keyset_id_active = (
            keysets_active[0]["id"] if keysets_active else proofs[0]["id"]
        )

        outputs, secrets, blinding_factors = self._create_blinded_messages_for_amount(
            total_amount, keyset_id_active
        )

        # Swap proofs for new ones
        response = await mint.swap(inputs=mint_proofs, outputs=outputs)

        # Get mint public key for unblinding
        keys_resp = await mint.get_keys()
        # Find the keyset matching our proofs
        mint_keys = None
        for ks in keys_resp.get("keysets", []):
            if ks["id"] == keyset_id_active:
                keys_data: str | dict[str, str] = ks.get("keys", {})
                if isinstance(keys_data, dict) and keys_data:
                    mint_keys = keys_data
                    break

        if not mint_keys:
            raise WalletError("Could not find mint keys")

        # Convert signatures to proofs
        new_proofs: list[ProofDict] = []
        for i, sig in enumerate(response["signatures"]):
            # Get the public key for this amount
            amount = sig["amount"]
            mint_pubkey = self._get_mint_pubkey_for_amount(mint_keys, amount)
            if not mint_pubkey:
                raise WalletError(f"Could not find mint public key for amount {amount}")

            # Unblind the signature
            C_ = PublicKey(bytes.fromhex(sig["C_"]))
            r = bytes.fromhex(blinding_factors[i])
            C = unblind_signature(C_, r, mint_pubkey)

            new_proofs.append(
                ProofDict(
                    id=sig["id"],
                    amount=sig["amount"],
                    secret=secrets[i],
                    C=C.format(compressed=True).hex(),
                    mint=mint_url,
                )
            )

        # Publish new token event
        token_event_id = await self.publish_token_event(new_proofs)

        # Publish spending history
        await self.publish_spending_history(
            direction="in",
            amount=total_amount,
            created_token_ids=[token_event_id],
        )

        return total_amount, unit

    async def swap_mints(
        self,
        token: str,
        *,
        target_mint: str | None = None,
        fee_reserve_percent: float = 0.01,
        min_amount_after_fees: int = 1,
    ) -> tuple[int, str]:
        """Swap tokens from any mint to a trusted mint via Lightning.

        This is useful for merchants accepting tokens from untrusted mints.
        The tokens are immediately melted from the source mint and minted
        at the target mint.

        Note: The redeem() method automatically calls this when receiving
        tokens from untrusted mints, so you typically don't need to call
        this directly unless you want explicit control over the target mint.

        Args:
            token: Cashu token to swap
            target_mint: Target mint URL (defaults to wallet's first mint)
            fee_reserve_percent: Lightning fee reserve as percentage (default: 1%)
            min_amount_after_fees: Minimum acceptable amount after fees (default: 1)

        Returns:
            Tuple of (amount_received, unit) at the target mint

        Raises:
            WalletError: If swap fails

        Example:
            # Explicitly swap to a specific mint (different from wallet's default)
            amount, unit = await wallet.swap_mints(
                untrusted_token,
                target_mint="https://my-specific-mint.com"
            )
        """
        # Parse the incoming token
        source_mint_url, unit, proofs = self._parse_cashu_token(token)
        total_amount = sum(p["amount"] for p in proofs)

        # Use default mint if no target specified
        if target_mint is None:
            if not self.mint_urls:
                raise WalletError(
                    "No target mint specified and no default mints configured"
                )
            target_mint = self.mint_urls[0]

        # Skip if source and target are the same
        if source_mint_url == target_mint:
            return await self.redeem(token)

        # Get mint instances
        source_mint = self._get_mint(source_mint_url)
        target_mint_obj = self._get_mint(target_mint)

        # Step 1: First, we need to estimate fees by creating a test melt quote
        # Create a small test invoice to check fee structure
        test_quote_resp = await target_mint_obj.create_mint_quote(
            unit=unit,
            amount=1,  # Minimal amount to test fees
        )
        test_invoice = test_quote_resp["request"]

        # Check fee structure with source mint
        test_melt_quote = await source_mint.create_melt_quote(
            unit=unit,
            request=test_invoice,
        )

        # Estimate fees as a percentage of amount (usually 1-3%)
        # Use the fee_reserve from test quote as a baseline
        fee_percentage = test_melt_quote.get("fee_reserve", 1) / 100.0
        estimated_fee = max(int(total_amount * fee_percentage), 1)

        # For small amounts, fees might be a fixed minimum
        if test_melt_quote.get("fee_reserve", 0) >= 1:
            # If fee reserve is significant for 1 sat, use a higher estimate
            estimated_fee = max(estimated_fee, test_melt_quote.get("fee_reserve", 0))

        # Step 2: Create mint quote at target mint for amount minus estimated fees
        amount_to_mint = total_amount - estimated_fee
        if amount_to_mint < min_amount_after_fees:
            raise WalletError(
                f"Token amount ({total_amount}) minus fees ({estimated_fee}) "
                f"would be {amount_to_mint}, below minimum ({min_amount_after_fees})"
            )

        quote_resp = await target_mint_obj.create_mint_quote(
            unit=unit,
            amount=amount_to_mint,
        )
        lightning_invoice = quote_resp["request"]
        quote_id = quote_resp["quote"]

        # Step 3: Create melt quote at source mint with actual invoice
        melt_quote = await source_mint.create_melt_quote(
            unit=unit,
            request=lightning_invoice,
        )

        # Check if we have enough to cover the actual fees
        required_amount = melt_quote["amount"] + melt_quote["fee_reserve"]
        if total_amount < required_amount:
            # Try again with a smaller amount
            amount_to_mint = total_amount - melt_quote["fee_reserve"]
            if amount_to_mint < min_amount_after_fees:
                raise WalletError(
                    f"Token amount ({total_amount}) minus fees ({melt_quote['fee_reserve']}) "
                    f"would be {amount_to_mint}, below minimum ({min_amount_after_fees})"
                )

            # Create new mint quote with adjusted amount
            quote_resp = await target_mint_obj.create_mint_quote(
                unit=unit,
                amount=amount_to_mint,
            )
            lightning_invoice = quote_resp["request"]
            quote_id = quote_resp["quote"]

            # Create new melt quote
            melt_quote = await source_mint.create_melt_quote(
                unit=unit,
                request=lightning_invoice,
            )

        # Step 4: Melt tokens at source mint to pay the invoice
        # Convert proofs to mint format
        mint_proofs: list[Proof] = []
        for p in proofs:
            mint_proofs.append(self._proofdict_to_mint_proof(p))

        # Execute melt (no outputs needed since we're spending all)
        try:
            _ = await source_mint.melt(
                quote=melt_quote["quote"],
                inputs=mint_proofs,
                outputs=None,
            )
        except Exception as e:
            raise WalletError(f"Failed to melt tokens from source mint: {str(e)}")

        # Step 5: Check that payment was successful at target mint
        quote_status = await target_mint_obj.get_mint_quote(quote_id)

        if not quote_status.get("paid") or quote_status.get("state") != "PAID":
            raise WalletError("Lightning payment failed during mint swap")

        # Step 6: Mint new tokens at target mint
        # Get active keyset from target mint
        keys_resp = await target_mint_obj.get_keys()
        keysets = keys_resp.get("keysets", [])
        if not keysets:
            raise WalletError("Target mint has no active keysets")
        keyset_id = keysets[0]["id"]

        # The amount we'll receive is what we requested to mint
        # (already accounts for fees in the mint quote)
        amount_received = amount_to_mint

        # Create outputs for the received amount
        outputs, secrets, blinding_factors = self._create_blinded_messages_for_amount(
            amount_received, keyset_id
        )

        # Mint new tokens
        mint_resp = await target_mint_obj.mint(quote=quote_id, outputs=outputs)

        # Get mint keys for unblinding
        mint_keys = None
        for ks in keys_resp.get("keysets", []):
            if ks["id"] == keyset_id:
                keys_data: str | dict[str, str] = ks.get("keys", {})
                if isinstance(keys_data, dict) and keys_data:
                    mint_keys = keys_data
                    break

        if not mint_keys:
            raise WalletError("Could not find target mint keys")

        # Convert signatures to proofs
        new_proofs: list[ProofDict] = []
        for i, sig in enumerate(mint_resp["signatures"]):
            # Get the public key for this amount
            amount = sig["amount"]
            mint_pubkey = self._get_mint_pubkey_for_amount(mint_keys, amount)
            if not mint_pubkey:
                raise WalletError(f"Could not find mint public key for amount {amount}")

            # Unblind the signature
            C_ = PublicKey(bytes.fromhex(sig["C_"]))
            r = bytes.fromhex(blinding_factors[i])
            C = unblind_signature(C_, r, mint_pubkey)

            new_proofs.append(
                ProofDict(
                    id=sig["id"],
                    amount=sig["amount"],
                    secret=secrets[i],
                    C=C.format(compressed=True).hex(),
                    mint=target_mint,
                )
            )

        # Publish new token event
        token_event_id = await self.publish_token_event(new_proofs)

        # Publish spending history
        await self.publish_spending_history(
            direction="in",
            amount=amount_received,
            created_token_ids=[token_event_id],
        )

        return amount_received, unit

    async def create_quote(self, amount: int) -> tuple[str, str]:
        """Create a Lightning invoice (quote) at the mint and return the BOLT-11 string and quote ID.

        Returns:
            Tuple of (lightning_invoice, quote_id)
        """
        mint = self._get_mint(self.mint_urls[0])

        # Create mint quote
        quote_resp = await mint.create_mint_quote(
            unit=self.currency,
            amount=amount,
        )

        # Optionally publish quote tracker event
        # (skipping for simplicity)

        # TODO: Implement quote tracking as per NIP-60:
        # await self.publish_quote_tracker(
        #     quote_id=quote_resp["quote"],
        #     mint_url=self.mint_urls[0],
        #     expiration=int(time.time()) + 14 * 24 * 60 * 60  # 2 weeks
        # )

        return quote_resp.get("request", ""), quote_resp.get(
            "quote", ""
        )  # Return both invoice and quote_id

    async def check_quote_status(
        self, quote_id: str, amount: int | None = None
    ) -> dict[str, object]:
        """Check whether a quote has been paid and redeem proofs if so."""
        mint = self._get_mint(self.mint_urls[0])

        # Check quote status
        quote_status = await mint.get_mint_quote(quote_id)

        if quote_status.get("paid") and quote_status.get("state") == "PAID":
            # Check if we've already minted for this quote
            if quote_id in self._minted_quotes:
                return dict(quote_status)

            # Mark this quote as being minted
            self._minted_quotes.add(quote_id)

            # Check if we've already minted for this quote
            # by seeing if we have a token event with this quote ID in tags
            # TODO: Properly track minted quotes to avoid double-minting
            # For now, we'll proceed with minting

            # Get amount from quote_status or use provided amount
            mint_amount = quote_status.get("amount", amount)
            if mint_amount is None:
                raise ValueError(
                    "Amount not available in quote status and not provided"
                )

            # Get active keyset
            keys_resp = await mint.get_keys()
            keysets = keys_resp.get("keysets", [])
            keyset_id = keysets[0]["id"] if keysets else ""

            # Simple denomination split using mint's active keyset id
            keys_resp_active = await mint.get_keys()
            keysets_active = keys_resp_active.get("keysets", [])
            keyset_id_active = keysets_active[0]["id"] if keysets_active else keyset_id

            # Create blinded messages for the amount
            outputs, secrets, blinding_factors = (
                self._create_blinded_messages_for_amount(mint_amount, keyset_id_active)
            )

            # Mint tokens
            mint_resp = await mint.mint(quote=quote_id, outputs=outputs)

            # Get mint public key for unblinding
            keys_resp = await mint.get_keys()
            mint_keys = None
            for ks in keys_resp.get("keysets", []):
                if ks["id"] == keyset_id_active:
                    keys_data: str | dict[str, str] = ks.get("keys", {})
                    if isinstance(keys_data, dict) and keys_data:
                        mint_keys = keys_data
                        break

            if not mint_keys:
                raise WalletError("Could not find mint keys")

            # Convert to proofs
            new_proofs: list[ProofDict] = []
            for i, sig in enumerate(mint_resp["signatures"]):
                # Get the public key for this amount
                amount = sig["amount"]
                mint_pubkey = self._get_mint_pubkey_for_amount(mint_keys, amount)
                if not mint_pubkey:
                    raise WalletError(
                        f"Could not find mint public key for amount {amount}"
                    )

                # Unblind the signature
                C_ = PublicKey(bytes.fromhex(sig["C_"]))
                r = bytes.fromhex(blinding_factors[i])
                C = unblind_signature(C_, r, mint_pubkey)

                new_proofs.append(
                    ProofDict(
                        id=sig["id"],
                        amount=sig["amount"],
                        secret=secrets[i],
                        C=C.format(compressed=True).hex(),
                        mint=self.mint_urls[0],
                    )
                )

            # Publish token event
            token_event_id = await self.publish_token_event(new_proofs)

            # Publish spending history
            await self.publish_spending_history(
                direction="in",
                amount=mint_amount,
                created_token_ids=[token_event_id],
            )

        return dict(quote_status)  # type: ignore

    async def mint_async(
        self, amount: int, *, timeout: int = 300
    ) -> tuple[str, asyncio.Task[bool]]:
        """Create a Lightning invoice and return a task that completes when paid.

        This returns immediately with the invoice and a background task that
        polls for payment.

        Args:
            amount: Amount in the wallet's currency unit
            timeout: Maximum seconds to wait for payment (default: 5 minutes)

        Returns:
            Tuple of (lightning_invoice, payment_task)
            The payment_task returns True when paid, False on timeout

        Example:
            invoice, task = await wallet.mint_async(100)
            print(f"Pay: {invoice}")
            # Do other things...
            paid = await task  # Wait for payment
        """
        invoice, quote_id = await self.create_quote(amount)

        async def poll_payment() -> bool:
            start_time = time.time()
            poll_interval = 1.0

            while (time.time() - start_time) < timeout:
                quote_status = await self.check_quote_status(quote_id, amount)
                if quote_status.get("paid"):
                    return True

                await asyncio.sleep(poll_interval)
                poll_interval = min(poll_interval * 1.2, 5.0)

            return False

        # Create background task
        task = asyncio.create_task(poll_payment())
        return invoice, task

    # ─────────────────────────────── Send ─────────────────────────────────────

    async def melt(self, invoice: str) -> None:
        """Pay a Lightning invoice by melting tokens with automatic multi-mint support.

        This enhanced implementation will:
        1. Check the invoice amount first
        2. Verify total balance across all mints
        3. If no single mint has enough, automatically swap proofs to consolidate
        4. Execute payment from the mint with sufficient balance

        Args:
            invoice: BOLT-11 Lightning invoice to pay

        Raises:
            WalletError: If insufficient balance or payment fails

        Example:
            await wallet.melt("lnbc100n1...")
        """
        # First, get the invoice amount by checking with any mint that supports this unit
        invoice_amount = None
        lightning_fee_estimate = 0
        capable_mints: list[
            tuple[str, Mint, PostMeltQuoteResponse]
        ] = []  # (url, mint, quote)

        # Check which mints can handle this invoice and get the amount
        for mint_url in self.mint_urls:
            try:
                mint = self._get_mint(mint_url)
                quote = await mint.create_melt_quote(
                    unit=self.currency,
                    request=invoice,
                )

                # Extract invoice amount from the first successful quote
                if invoice_amount is None:
                    invoice_amount = int(quote.get("amount", 0))
                    # Use the highest fee estimate we see
                    fee_reserve = int(quote.get("fee_reserve", 0))
                    lightning_fee_estimate = max(lightning_fee_estimate, fee_reserve)

                capable_mints.append((mint_url, mint, quote))
            except Exception:
                # This mint can't handle the invoice, skip it
                continue

        if not capable_mints:
            raise WalletError("No mint can handle this invoice")

        if invoice_amount is None or invoice_amount == 0:
            raise WalletError("Could not determine invoice amount")

        # Get current wallet state to check total balance
        state = await self.fetch_wallet_state(check_proofs=True)
        total_balance = state.balance

        # Group proofs by mint for balance checking
        proofs_by_mint: dict[str, list[ProofDict]] = {}
        for proof in state.proofs:
            mint_url = proof.get("mint") or (
                self.mint_urls[0] if self.mint_urls else ""
            )
            if mint_url not in proofs_by_mint:
                proofs_by_mint[mint_url] = []
            proofs_by_mint[mint_url].append(proof)

        # Calculate total fees needed (lightning + estimated input fees)
        # Estimate ~2-3 proofs will be used, with average fee of 1 sat per proof
        estimated_input_fees = 3  # Conservative estimate
        total_amount_needed = (
            invoice_amount + lightning_fee_estimate + estimated_input_fees
        )

        # Check if we have enough total balance
        if total_balance < total_amount_needed:
            raise WalletError(
                f"Insufficient total balance. Need {total_amount_needed} "
                f"(invoice: {invoice_amount}, fees: ~{lightning_fee_estimate + estimated_input_fees}), "
                f"have {total_balance}"
            )

        # Check each capable mint's balance
        selected_mint_url = None
        selected_mint = None
        selected_quote = None
        mint_balances: dict[str, int] = {}

        for mint_url, mint, quote in capable_mints:
            mint_proofs = proofs_by_mint.get(mint_url, [])
            mint_balance = sum(p["amount"] for p in mint_proofs)
            mint_balances[mint_url] = mint_balance

            # Calculate actual input fees for this mint's proofs
            try:
                actual_input_fees = await self.calculate_total_input_fees(
                    mint, mint_proofs[:5]
                )  # Estimate with first 5 proofs
                # Scale up the estimate based on total proofs needed
                proofs_needed = (
                    total_amount_needed + mint_balance - 1
                ) // mint_balance  # Ceiling division
                estimated_mint_fees = actual_input_fees * proofs_needed
            except Exception:
                estimated_mint_fees = estimated_input_fees

            # Check if this mint has enough balance
            if (
                mint_balance
                >= invoice_amount
                + int(quote.get("fee_reserve", 0))
                + estimated_mint_fees
            ):
                selected_mint_url = mint_url
                selected_mint = mint
                selected_quote = quote
                break

        # If no single mint has enough, we need to consolidate proofs
        if selected_mint_url is None:
            # Find the mint with the highest balance among capable mints
            if mint_balances:
                target_mint_url = max(
                    mint_balances.keys(), key=lambda k: mint_balances[k]
                )

                # Find the corresponding mint and quote
                for mint_url, mint, quote in capable_mints:
                    if mint_url == target_mint_url:
                        selected_mint_url = mint_url
                        selected_mint = mint
                        selected_quote = quote
                        break

                # Calculate how much we need to transfer to the target mint
                current_balance = mint_balances[target_mint_url]
                amount_to_transfer = (
                    total_amount_needed - current_balance + 10
                )  # Add small buffer

                # Collect proofs from other mints to swap
                proofs_to_swap: list[ProofDict] = []
                collected_amount = 0

                for mint_url, proofs in proofs_by_mint.items():
                    if mint_url == target_mint_url:
                        continue  # Skip the target mint

                    for proof in proofs:
                        if collected_amount >= amount_to_transfer:
                            break
                        proofs_to_swap.append(proof)
                        collected_amount += proof["amount"]

                    if collected_amount >= amount_to_transfer:
                        break

                if collected_amount < amount_to_transfer:
                    raise WalletError(
                        f"Cannot consolidate enough proofs. Need {amount_to_transfer}, "
                        f"collected {collected_amount} from other mints"
                    )

                # Perform the swap to consolidate proofs at target mint
                print(
                    f"Consolidating {collected_amount} from other mints to {target_mint_url}..."
                )

                # Create a token from the proofs to swap
                # Group by source mint for proper token creation
                swap_tokens: list[str] = []
                for source_mint_url in set(p.get("mint", "") for p in proofs_to_swap):
                    if not source_mint_url:  # Skip empty mint URLs
                        continue
                    mint_proofs = [
                        p
                        for p in proofs_to_swap
                        if p.get("mint", "") == source_mint_url
                    ]
                    if mint_proofs:
                        token = self._serialize_proofs_for_token(
                            mint_proofs, source_mint_url
                        )
                        swap_tokens.append(token)

                # Redeem each token at the target mint
                for token in swap_tokens:
                    await self.swap_mints(token, target_mint=target_mint_url)

                print(f"Successfully consolidated proofs at {target_mint_url}")

        # Now we have a mint with sufficient balance, proceed with standard melt
        if not selected_mint or not selected_quote:
            raise WalletError("Failed to select mint for payment")

        # Re-fetch proofs after potential consolidation
        if len(swap_tokens if "swap_tokens" in locals() else []) > 0:
            state = await self.fetch_wallet_state(check_proofs=True)
            proofs_by_mint = {}
            for proof in state.proofs:
                mint_url = proof.get("mint") or (
                    self.mint_urls[0] if self.mint_urls else ""
                )
                if mint_url not in proofs_by_mint:
                    proofs_by_mint[mint_url] = []
                proofs_by_mint[mint_url].append(proof)

        # Select proofs from the chosen mint
        if selected_mint_url:
            mint_proofs_for_spend = proofs_by_mint.get(selected_mint_url, [])
        else:
            # This should not happen, but handle gracefully
            raise WalletError("No mint selected for payment")

        lightning_fee_reserve = int(selected_quote.get("fee_reserve", 0))

        # Select proofs to spend
        (
            selected_proofs,
            selected_amount,
            events_to_delete,
        ) = await self._select_proofs_for_amount(
            invoice_amount + lightning_fee_reserve, mint_filter=selected_mint_url
        )

        # Calculate actual input fees
        try:
            input_fees = await self.calculate_total_input_fees(
                selected_mint, selected_proofs
            )
        except Exception:
            input_fees = 0

        # Total amount needed including all fees
        total_needed = invoice_amount + lightning_fee_reserve + input_fees

        # Check if we need more proofs to cover input fees
        if selected_amount < total_needed:
            (
                selected_proofs,
                selected_amount,
                events_to_delete,
            ) = await self._select_proofs_for_amount(
                total_needed, mint_filter=selected_mint_url
            )

            # Recalculate input fees with new selection
            try:
                input_fees = await self.calculate_total_input_fees(
                    selected_mint, selected_proofs
                )
                total_needed = invoice_amount + lightning_fee_reserve + input_fees
            except Exception:
                input_fees = 0
                total_needed = invoice_amount + lightning_fee_reserve

        # Filter proofs to only those with valid keysets
        selected_proofs = await self._filter_proofs_by_keyset(
            selected_mint,
            selected_proofs,
            total_needed,
            operation=f"melt {invoice_amount} from mint {selected_mint_url}",
        )

        # Convert to mint proofs
        proofs_for_melt: list[Proof] = []
        for p in selected_proofs:
            proofs_for_melt.append(self._proofdict_to_mint_proof(p))

        # Calculate change amount
        change_amount = selected_amount - total_needed
        if change_amount > 0:
            keyset_id = selected_proofs[0]["id"]

            # Use the mint's currently active keyset for outputs
            keys_resp_active = await selected_mint.get_keys()
            keysets_active = keys_resp_active.get("keysets", [])
            keyset_id_active = keysets_active[0]["id"] if keysets_active else keyset_id

            # Create blinded messages for change
            change_outputs, change_secrets, change_blinding_factors = (
                self._create_blinded_messages_for_amount(
                    change_amount, keyset_id_active
                )
            )
        else:
            change_outputs = []
            change_secrets = []
            change_blinding_factors = []

        # Execute melt
        melt_resp = await selected_mint.melt(
            quote=selected_quote["quote"],
            inputs=proofs_for_melt,
            outputs=change_outputs if change_outputs else None,
        )

        # Process change if any
        mint_keys = None
        if change_outputs and melt_resp.get("change"):
            # Get mint public key for unblinding change
            keys_resp = await selected_mint.get_keys()
            for ks in keys_resp.get("keysets", []):
                if ks["id"] == keyset_id_active:
                    keys_data: str | dict[str, str] = ks.get("keys", {})
                    if isinstance(keys_data, dict) and keys_data:
                        mint_keys = keys_data
                        break

        # Delete old token events
        old_token_ids = list(events_to_delete)

        # Create new token event for change
        created_ids = []
        if change_outputs and melt_resp.get("change") and mint_keys:
            change_proofs: list[ProofDict] = []
            for i, sig in enumerate(melt_resp["change"]):
                # Get the public key for this amount
                amount = sig["amount"]
                mint_pubkey = self._get_mint_pubkey_for_amount(mint_keys, amount)
                if not mint_pubkey:
                    raise WalletError(
                        f"Could not find mint public key for amount {amount}"
                    )

                # Unblind the signature
                C_ = PublicKey(bytes.fromhex(sig["C_"]))
                r = bytes.fromhex(change_blinding_factors[i])
                C = unblind_signature(C_, r, mint_pubkey)

                change_proofs.append(
                    ProofDict(
                        id=sig["id"],
                        amount=sig["amount"],
                        secret=change_secrets[i],
                        C=C.format(compressed=True).hex(),
                        mint=selected_mint_url,
                    )
                )
            token_event_id = await self.publish_token_event(
                change_proofs,
                deleted_token_ids=old_token_ids,
            )
            created_ids = [token_event_id]

        # Publish spending history with fee information
        await self.publish_spending_history(
            direction="out",
            amount=invoice_amount + input_fees,  # Include input fees in spending amount
            created_token_ids=created_ids,
            destroyed_token_ids=old_token_ids,
        )

    async def send(self, amount: int) -> str:
        """Create a Cashu token for sending.

        Selects proofs worth at least the specified amount and returns a
        Cashu token string. If the selected proofs are worth more than the
        amount, change proofs will be created and stored.

        Args:
            amount: Amount to send in the wallet's currency unit

        Returns:
            Cashu token string that can be sent to another wallet

        Raises:
            WalletError: If insufficient balance or operation fails

        Example:
            token = await wallet.send(100)
            print(f"Send this token: {token}")
        """
        # Select proofs for the amount
        (
            selected_proofs,
            selected_amount,
            events_to_delete,
        ) = await self._select_proofs_for_amount(amount)

        if not selected_proofs:
            raise WalletError(f"Insufficient balance. Need {amount}")

        # Group proofs by mint for fee calculation
        proofs_by_mint: dict[str, list[ProofDict]] = {}
        for proof in selected_proofs:
            mint_url = proof.get("mint") or (
                self.mint_urls[0] if self.mint_urls else ""
            )
            if mint_url not in proofs_by_mint:
                proofs_by_mint[mint_url] = []
            proofs_by_mint[mint_url].append(proof)

        # Calculate input fees for all mints involved
        total_input_fees = 0
        for mint_url, mint_proofs in proofs_by_mint.items():
            try:
                mint = self._get_mint(mint_url)
                mint_input_fees = await self.calculate_total_input_fees(
                    mint, mint_proofs
                )
                total_input_fees += mint_input_fees
            except Exception:
                # Fallback to zero fees if calculation fails
                continue

        # Check if we need more proofs to cover input fees
        total_amount_needed = amount + total_input_fees
        if selected_amount < total_amount_needed:
            # Need to select more proofs to cover input fees
            (
                selected_proofs,
                selected_amount,
                events_to_delete,
            ) = await self._select_proofs_for_amount(total_amount_needed)

            # Recalculate input fees with new proof selection
            proofs_by_mint = {}
            for proof in selected_proofs:
                mint_url = proof.get("mint") or (
                    self.mint_urls[0] if self.mint_urls else ""
                )
                if mint_url not in proofs_by_mint:
                    proofs_by_mint[mint_url] = []
                proofs_by_mint[mint_url].append(proof)

            total_input_fees = 0
            for mint_url, mint_proofs in proofs_by_mint.items():
                try:
                    mint = self._get_mint(mint_url)
                    mint_input_fees = await self.calculate_total_input_fees(
                        mint, mint_proofs
                    )
                    total_input_fees += mint_input_fees
                except Exception:
                    continue

        # Determine which mint to use (prefer the one with most proofs)
        selected_mint_url = max(
            proofs_by_mint.keys(), key=lambda k: len(proofs_by_mint[k])
        )
        mint = self._get_mint(selected_mint_url)

        remaining_proofs: list[ProofDict] = []

        # If we selected too much, need to split
        total_amount_with_fees = amount + total_input_fees
        if selected_amount > total_amount_with_fees:
            # Filter proofs to only those with valid keysets for this mint
            selected_proofs = await self._filter_proofs_by_keyset(
                mint,
                selected_proofs,
                total_amount_with_fees,
                operation=f"send {amount} from mint {selected_mint_url}",
            )
            # Recalculate selected amount after filtering
            selected_amount = sum(p["amount"] for p in selected_proofs)

            # Convert to mint proofs
            mint_proofs_for_swap: list[Proof] = []
            for p in selected_proofs:
                mint_proofs_for_swap.append(self._proofdict_to_mint_proof(p))

            # Use the mint's currently active keyset for outputs
            keyset_id = selected_proofs[0]["id"]
            keys_resp_active = await mint.get_keys()
            keysets_active = keys_resp_active.get("keysets", [])
            keyset_id_active = keysets_active[0]["id"] if keysets_active else keyset_id

            # Create outputs for exact amount
            send_outputs, send_secrets, send_blinding_factors = (
                self._create_blinded_messages_for_amount(amount, keyset_id_active)
            )

            # Create outputs for change
            change_amount = selected_amount - amount
            change_outputs, change_secrets, change_blinding_factors = (
                self._create_blinded_messages_for_amount(
                    change_amount, keyset_id_active
                )
            )

            # Combine all outputs, secrets, and blinding factors
            outputs = send_outputs + change_outputs
            all_secrets = send_secrets + change_secrets
            all_blinding_factors = send_blinding_factors + change_blinding_factors

            # Swap for exact denominations
            swap_resp = await mint.swap(inputs=mint_proofs_for_swap, outputs=outputs)

            # Get mint public key for unblinding
            keys_resp = await mint.get_keys()
            mint_keys = None
            for ks in keys_resp.get("keysets", []):
                if ks["id"] == keyset_id_active:
                    keys_data: str | dict[str, str] = ks.get("keys", {})
                    if isinstance(keys_data, dict) and keys_data:
                        mint_keys = keys_data
                        break

            if not mint_keys:
                raise WalletError("Could not find mint keys")

            # Separate send and change proofs
            send_proofs: list[ProofDict] = []
            change_proofs: list[ProofDict] = []

            for i, sig in enumerate(swap_resp["signatures"]):
                # Get the public key for this amount
                amount_val = sig["amount"]
                mint_pubkey = self._get_mint_pubkey_for_amount(mint_keys, amount_val)
                if not mint_pubkey:
                    raise WalletError(
                        f"Could not find mint public key for amount {amount_val}"
                    )

                # Unblind the signature
                C_ = PublicKey(bytes.fromhex(sig["C_"]))
                r = bytes.fromhex(all_blinding_factors[i])
                C = unblind_signature(C_, r, mint_pubkey)

                proof = ProofDict(
                    id=sig["id"],
                    amount=sig["amount"],
                    secret=all_secrets[i],
                    C=C.format(compressed=True).hex(),
                    mint=selected_mint_url,
                )

                if i < len(send_outputs):
                    send_proofs.append(proof)
                else:
                    change_proofs.append(proof)

            # Update remaining proofs with change proofs
            remaining_proofs.extend(change_proofs)
            selected_proofs = send_proofs

        # Create Cashu token
        token = self._serialize_proofs_for_token(selected_proofs, selected_mint_url)

        # Delete old token events and create new one for remaining
        deleted_event_ids = list(events_to_delete)

        if remaining_proofs:
            # Group remaining proofs by mint for publishing
            remaining_by_mint: dict[str, list[ProofDict]] = {}
            for proof in remaining_proofs:
                mint_url = proof.get("mint") or selected_mint_url
                if mint_url not in remaining_by_mint:
                    remaining_by_mint[mint_url] = []
                remaining_by_mint[mint_url].append(proof)

            # Publish token events for each mint
            created_ids: list[str] = []
            for mint_url, mint_proofs in remaining_by_mint.items():
                token_event_id = await self.publish_token_event(
                    mint_proofs,
                    deleted_token_ids=deleted_event_ids if not created_ids else None,
                )
                created_ids.append(token_event_id)
        else:
            # Still need to delete old events even if no remaining proofs
            for event_id in deleted_event_ids:
                await self.delete_token_event(event_id)
            created_ids = []

        # Publish spending history with fee information
        await self.publish_spending_history(
            direction="out",
            amount=amount + total_input_fees,  # Include input fees in spending amount
            created_token_ids=created_ids,
            destroyed_token_ids=deleted_event_ids,
        )

        return token

    async def send_to_lnurl(
        self,
        lnurl: str,
        amount: int,
        *,
        fee_estimate: float = 0.01,
        max_fee: int | None = None,
        mint_fee_reserve: int = 1,
    ) -> int:
        """Send funds to an LNURL address.

        Args:
            lnurl: LNURL string (can be lightning:, user@host, bech32, or direct URL)
            amount: Amount to send in the wallet's currency unit
            fee_estimate: Fee estimate as a percentage (default: 1%)
            max_fee: Maximum fee in the wallet's currency unit (optional)
            mint_fee_reserve: Expected mint fee reserve (default: 1 sat)

        Returns:
            Amount actually paid in the wallet's currency unit

        Raises:
            WalletError: If amount is outside LNURL limits or insufficient balance
            LNURLError: If LNURL operations fail

        Example:
            # Send 1000 sats to a Lightning Address
            paid = await wallet.send_to_lnurl("user@getalby.com", 1000)
            print(f"Paid {paid} sats")
        """
        from .lnurl import get_lnurl_data, get_lnurl_invoice

        # Get current balance
        state = await self.fetch_wallet_state(check_proofs=True)
        balance = state.balance

        # Check if we have enough balance for amount + mint fees
        min_required_balance = amount + mint_fee_reserve
        if balance < min_required_balance:
            raise WalletError(
                f"Insufficient balance. Need at least {min_required_balance} {self.currency} "
                f"(amount: {amount} + mint fees: {mint_fee_reserve}), but have {balance}"
            )

        # Get LNURL data
        lnurl_data = await get_lnurl_data(lnurl)

        # Convert amounts based on currency
        if self.currency == "sat":
            amount_msat = amount * 1000
            min_sendable_sat = lnurl_data["min_sendable"] // 1000
            max_sendable_sat = lnurl_data["max_sendable"] // 1000
            unit_str = "sat"
        elif self.currency == "msat":
            amount_msat = amount
            min_sendable_sat = lnurl_data["min_sendable"]
            max_sendable_sat = lnurl_data["max_sendable"]
            unit_str = "msat"
        else:
            raise WalletError(f"Currency {self.currency} not supported for LNURL")

        # Check amount limits
        if not (
            lnurl_data["min_sendable"] <= amount_msat <= lnurl_data["max_sendable"]
        ):
            raise WalletError(
                f"Amount {amount} {unit_str} is outside LNURL limits "
                f"({min_sendable_sat} - {max_sendable_sat} {unit_str})"
            )

        # For small amounts or when balance is tight, request the full amount
        # and let mint fees come from any excess balance
        if amount <= 10 or balance <= min_required_balance + 2:
            amount_to_request = amount_msat
        else:
            # For larger amounts with comfortable balance, try to optimize fees
            estimated_fee = int(amount * fee_estimate)
            if max_fee is not None:
                estimated_fee = min(estimated_fee, max_fee)
            estimated_fee = max(estimated_fee, 1)  # Minimum 1 unit fee

            amount_to_request = amount_msat - (
                estimated_fee * (1000 if self.currency == "sat" else 1)
            )

            # Ensure amount_to_request meets LNURL minimum requirements
            if amount_to_request < lnurl_data["min_sendable"]:
                amount_to_request = amount_msat

        # Get Lightning invoice
        bolt11_invoice, invoice_data = await get_lnurl_invoice(
            lnurl_data["callback_url"], amount_to_request
        )

        # Get balance before payment (with fresh state)
        state_before = await self.fetch_wallet_state(check_proofs=True)
        balance_before = state_before.balance

        # Pay the invoice using melt
        await self.melt(bolt11_invoice)

        # Wait a bit for state to propagate to relays
        await asyncio.sleep(0.5)

        # Get balance after payment to calculate actual amount paid
        try:
            state_after = await self.fetch_wallet_state(check_proofs=True)
            balance_after = state_after.balance
            actual_paid = balance_before - balance_after
        except Exception:
            # If we can't get updated state, estimate based on invoice amount
            if self.currency == "sat":
                # Add estimated Lightning routing fee (typically 1-3 sats for small amounts)
                actual_paid = (
                    amount_to_request + 999
                ) // 1000 + 2  # Invoice + ~2 sat fee
            else:  # msat
                actual_paid = amount_to_request + 2000  # Add ~2000 msat fee

        # Return the actual amount paid from the wallet
        return actual_paid

    async def roll_over_proofs(
        self,
        *,
        spent_proofs: list[ProofDict],
        unspent_proofs: list[ProofDict],
        deleted_event_ids: list[str],
    ) -> str:
        """Roll over unspent proofs after a partial spend and return new token id."""
        # Delete old token events
        for event_id in deleted_event_ids:
            await self.delete_token_event(event_id)

        # Create new token event with unspent proofs
        return await self.publish_token_event(
            unspent_proofs,
            deleted_token_ids=deleted_event_ids,
        )

    # ─────────────────────────────── Cleanup ──────────────────────────────────

    async def aclose(self) -> None:
        """Close underlying HTTP clients."""
        await self.mint_client.aclose()

        # Close relay connections
        for relay in self.relay_instances:
            await relay.disconnect()

        # Close mint clients
        for mint in self.mints.values():
            await mint.aclose()

    # ───────────────────────── Async context manager ──────────────────────────

    async def __aenter__(self) -> "Wallet":
        """Enter async context and auto-initialize wallet."""
        try:
            # Try to fetch existing wallet state with proof validation
            await self.fetch_wallet_state(check_proofs=True)
        except Exception:
            # If no wallet exists or fetch fails, create a new wallet event
            try:
                await self.create_wallet_event()
            except Exception:
                # If we can't create a wallet event, that's okay -
                # user might just want to do offline operations
                pass
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:  # noqa: D401  (simple return)
        await self.aclose()

    # ───────────────────────── Factory Methods ────────────────────────────────

    @classmethod
    async def create(
        cls,
        nsec: str,
        *,
        mint_urls: list[str] | None = None,
        currency: CurrencyUnit = "sat",
        wallet_privkey: str | None = None,
        relays: list[str] | None = None,
        auto_init: bool = True,
    ) -> "Wallet":
        """Create and optionally initialize a wallet with network operations.

        Args:
            nsec: Nostr private key
            mint_urls: Cashu mint URLs
            currency: Currency unit
            wallet_privkey: Private key for P2PK operations
            relays: Nostr relay URLs
            auto_init: If True, create wallet event and fetch state

        Returns:
            Initialized wallet instance
        """
        wallet = cls(
            nsec=nsec,
            mint_urls=mint_urls,
            currency=currency,
            wallet_privkey=wallet_privkey,
            relays=relays,
        )

        if auto_init:
            try:
                # Try to fetch existing state first with proof validation
                await wallet.fetch_wallet_state(check_proofs=True)
            except Exception:
                # If no wallet exists, create one
                await wallet.create_wallet_event()

        return wallet

    def _proofdict_to_mint_proof(self, proof_dict: ProofDict) -> Proof:
        """Convert ProofDict (with base64 secret) to Proof (with hex secret) for mint.

        NIP-60 stores secrets as base64, but Cashu protocol expects hex.
        """
        # Decode base64 secret to get raw bytes
        try:
            secret_bytes = base64.b64decode(proof_dict["secret"])
            secret_hex = secret_bytes.hex()
        except Exception:
            # Fallback: assume it's already hex (backwards compatibility)
            secret_hex = proof_dict["secret"]

        return Proof(
            id=proof_dict["id"],
            amount=proof_dict["amount"],
            secret=secret_hex,  # Mint expects hex
            C=proof_dict["C"],
        )

    def calculate_input_fees(self, proofs: list[ProofDict], keyset_info: dict) -> int:
        """Calculate input fees based on number of proofs and keyset fee rate.

        Args:
            proofs: List of proofs being spent
            keyset_info: Keyset information containing input_fee_ppk

        Returns:
            Total input fees in base currency units (e.g., satoshis)

        Example:
            With input_fee_ppk=1000 (1 sat per proof) and 3 proofs:
            fee = (3 * 1000) // 1000 = 3 satoshis
        """
        input_fee_ppk = keyset_info.get("input_fee_ppk", 0)

        # Ensure input_fee_ppk is an integer (could be string from API)
        try:
            input_fee_ppk = int(input_fee_ppk)
        except (ValueError, TypeError):
            input_fee_ppk = 0

        if input_fee_ppk == 0:
            return 0

        num_proofs = len(proofs)
        # Fee is calculated as: (number_of_proofs * input_fee_ppk) / 1000
        # Using integer division to avoid floating point precision issues
        return (num_proofs * input_fee_ppk) // 1000

    async def calculate_total_input_fees(
        self, mint: Mint, proofs: list[ProofDict]
    ) -> int:
        """Calculate total input fees for proofs across different keysets.

        Args:
            mint: Mint instance to query keyset information
            proofs: List of proofs being spent

        Returns:
            Total input fees for all proofs
        """
        try:
            # Get keyset information from mint
            keysets_resp = await mint.get_keysets()
            keyset_fees = {}

            # Build mapping of keyset_id -> input_fee_ppk
            for keyset in keysets_resp["keysets"]:
                keyset_fees[keyset["id"]] = keyset.get("input_fee_ppk", 0)

            # Group proofs by keyset and calculate fees
            total_fee = 0
            keyset_proof_counts = {}

            for proof in proofs:
                keyset_id = proof["id"]
                if keyset_id not in keyset_proof_counts:
                    keyset_proof_counts[keyset_id] = 0
                keyset_proof_counts[keyset_id] += 1

            # Calculate fees for each keyset
            for keyset_id, proof_count in keyset_proof_counts.items():
                fee_rate = keyset_fees.get(keyset_id, 0)
                # Ensure fee_rate is an integer (could be string from API)
                try:
                    fee_rate = int(fee_rate)
                except (ValueError, TypeError):
                    fee_rate = 0
                keyset_fee = (proof_count * fee_rate) // 1000
                total_fee += keyset_fee

            return total_fee

        except Exception:
            # Fallback to zero fees if keyset info unavailable
            # This ensures wallet doesn't break when connecting to older mints
            return 0

    def estimate_transaction_fees(
        self,
        input_proofs: list[ProofDict],
        keyset_info: dict,
        lightning_fee_reserve: int = 0,
    ) -> tuple[int, int]:
        """Estimate total transaction fees including input fees and lightning fees.

        Args:
            input_proofs: Proofs being spent as inputs
            keyset_info: Keyset information for input fee calculation
            lightning_fee_reserve: Lightning network fee reserve from melt quote

        Returns:
            Tuple of (input_fees, total_fees)
        """
        input_fees = self.calculate_input_fees(input_proofs, keyset_info)
        total_fees = input_fees + lightning_fee_reserve

        return input_fees, total_fees

    async def _select_proofs_for_amount(
        self, amount: int, mint_filter: str | None = None
    ) -> tuple[list[ProofDict], int, set[str]]:
        """Select proofs worth at least the specified amount.

        Args:
            amount: Minimum amount needed
            mint_filter: Optional mint URL to filter proofs by

        Returns:
            Tuple of (selected_proofs, total_amount, events_to_delete)
        """
        # Get current wallet state with proof validation
        state = await self.fetch_wallet_state(check_proofs=True)

        # Filter proofs by mint if specified
        available_proofs = []
        if mint_filter:
            for proof in state.proofs:
                proof_mint = proof.get("mint") or (
                    self.mint_urls[0] if self.mint_urls else ""
                )
                if proof_mint == mint_filter:
                    available_proofs.append(proof)
        else:
            available_proofs = state.proofs

        # Sort proofs by amount (ascending) for efficient selection
        available_proofs.sort(key=lambda p: p["amount"])

        selected_proofs: list[ProofDict] = []
        selected_amount = 0
        events_to_delete: set[str] = set()
        proof_to_event_id = state.proof_to_event_id or {}

        # Select proofs until we have enough
        for proof in available_proofs:
            if selected_amount >= amount:
                break

            selected_proofs.append(proof)
            selected_amount += proof["amount"]

            # Track which event this proof came from for deletion
            proof_id = f"{proof['secret']}:{proof['C']}"
            if proof_id in proof_to_event_id:
                events_to_delete.add(proof_to_event_id[proof_id])

        return selected_proofs, selected_amount, events_to_delete

    async def _filter_proofs_by_keyset(
        self,
        mint: Mint,
        proofs: list[ProofDict],
        required_amount: int,
        *,
        operation: str = "spend",
    ) -> list[ProofDict]:
        """Filter proofs to only those with valid keysets for the given mint.

        Args:
            mint: The mint instance to validate against
            proofs: List of proofs to filter
            required_amount: Minimum amount needed after filtering
            operation: Description of the operation for error messages

        Returns:
            Filtered list of proofs with valid keysets

        Raises:
            WalletError: If not enough valid proofs to meet required_amount
        """
        # Simply return all proofs - let the mint validate them
        # The previous implementation was too restrictive, filtering out proofs
        # with inactive keysets that are still valid and spendable
        return proofs


class TempWallet(Wallet):
    """Temporary wallet that generates a new random private key without storing it.

    This wallet creates a new random Nostr private key on initialization and
    operates entirely in memory. The private key is not stored or persisted
    anywhere, making it suitable for ephemeral operations.
    """

    def __init__(
        self,
        *,
        mint_urls: list[str] | None = None,
        currency: CurrencyUnit = "sat",
        wallet_privkey: str | None = None,
        relays: list[str] | None = None,
    ) -> None:
        """Initialize temporary wallet with a new random private key.

        Args:
            mint_urls: Cashu mint URLs (defaults to minibits mint)
            currency: Currency unit (sat, msat, or usd)
            wallet_privkey: Private key for P2PK operations (generated if not provided)
            relays: Nostr relay URLs to use
        """
        # Generate a new random private key
        temp_privkey = PrivateKey()
        temp_nsec = self._encode_nsec(temp_privkey)

        # Initialize parent with generated nsec
        super().__init__(
            nsec=temp_nsec,
            mint_urls=mint_urls,
            currency=currency,
            wallet_privkey=wallet_privkey,
            relays=relays,
        )

    def _encode_nsec(self, privkey: PrivateKey) -> str:
        """Encode private key as nsec (bech32) format.

        Args:
            privkey: The private key to encode

        Returns:
            nsec-encoded private key string
        """
        # Try to use bech32 encoding if available
        if bech32_decode is not None and convertbits is not None:
            from bech32 import bech32_encode  # type: ignore

            # Convert private key bytes to 5-bit groups for bech32
            key_bytes = privkey.secret
            converted = convertbits(key_bytes, 8, 5, pad=True)
            if converted is not None:
                encoded = bech32_encode("nsec", converted)
                if encoded:
                    return encoded

        # Fallback to hex encoding with nsec prefix
        return f"nsec_{privkey.to_hex()}"

    @classmethod
    async def create(  # type: ignore[override]
        cls,
        *,
        mint_urls: list[str] | None = None,
        currency: CurrencyUnit = "sat",
        wallet_privkey: str | None = None,
        relays: list[str] | None = None,
        auto_init: bool = True,
    ) -> "TempWallet":
        """Create and optionally initialize a temporary wallet.

        Args:
            mint_urls: Cashu mint URLs
            currency: Currency unit
            wallet_privkey: Private key for P2PK operations
            relays: Nostr relay URLs
            auto_init: If True, create wallet event and fetch state

        Returns:
            Initialized temporary wallet instance
        """
        wallet = cls(
            mint_urls=mint_urls,
            currency=currency,
            wallet_privkey=wallet_privkey,
            relays=relays,
        )

        if auto_init:
            try:
                # Try to fetch existing state first with proof validation
                await wallet.fetch_wallet_state(check_proofs=True)
            except Exception:
                # If no wallet exists, create one
                await wallet.create_wallet_event()

        return wallet


async def redeem_to_lnurl(token: str, lnurl: str, *, mint_fee_reserve: int = 1) -> int:
    """Redeem a token to an LNURL address and return the amount sent.

    This function automatically handles fees by reducing the send amount if needed.

    Args:
        token: Cashu token to redeem
        lnurl: LNURL/Lightning Address to send to
        mint_fee_reserve: Expected mint fee reserve (default: 1 sat)

    Returns:
        Amount actually sent (after fees)

    Raises:
        WalletError: If redeemed amount is too small (<=1 sat)
    """
    async with TempWallet() as wallet:
        amount, unit = await wallet.redeem(token)

        # Check if amount is too small
        if amount <= mint_fee_reserve:
            raise WalletError(
                f"Redeemed amount ({amount} {unit}) is too small. "
                f"After fees, nothing would be left to send."
            )

        # Try to send the full amount first
        try:
            paid = await wallet.send_to_lnurl(
                lnurl, amount, mint_fee_reserve=mint_fee_reserve
            )
            return paid
        except WalletError as e:
            # If insufficient balance due to fees, automatically adjust
            if "Insufficient balance" in str(e) and amount > mint_fee_reserve:
                # Send amount minus fee reserve
                adjusted_amount = amount - mint_fee_reserve
                paid = await wallet.send_to_lnurl(
                    lnurl, adjusted_amount, mint_fee_reserve=mint_fee_reserve
                )
                return paid
            raise
