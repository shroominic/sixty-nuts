import asyncio
import os
from dotenv import load_dotenv
from sixty_nuts.wallet import Wallet, EventKind


async def clear_wallet():
    """Clear all tokens from a wallet."""
    load_dotenv()
    nsec = os.getenv("NSEC")
    if not nsec:
        print("Error: NSEC environment variable not set. Please create a .env file.")
        return
    async with Wallet(
        nsec=nsec,
    ) as wallet:
        print("Clearing wallet tokens...")

        # Check current balance
        balance = await wallet.get_balance()
        print(f"Current balance: {balance} sats")

        if balance == 0:
            print("Wallet is already empty")
            return
          
        # Get relay connections and fetch events
        relays = await wallet._get_relay_connections()
        pubkey = wallet._get_pubkey()

        all_events = []
        event_ids_seen = set()

        print("Fetching wallet events from relays...")
        for relay in relays:
            try:
                events = await relay.fetch_wallet_events(pubkey)
                for event in events:
                    if event["id"] not in event_ids_seen:
                        all_events.append(event)
                        event_ids_seen.add(event["id"])
            except Exception as e:
                print(f"Error fetching from relay: {e}")
                continue

        # Filter for token events
        token_events = [e for e in all_events if e["kind"] == EventKind.Token]

        # Collect event IDs to delete from the proofs
        event_ids_to_delete = set()
        if state.proofs:
            for proof in state.proofs:
                proof_id = f"{proof['secret']}:{proof['C']}" # Reconstruct proof_id for lookup
                if proof_id in state.proof_to_event_id:
                    event_ids_to_delete.add(state.proof_to_event_id[proof_id])

        if not event_ids_to_delete:
            print("No token events found to delete from current proofs.")
            return

        # Enhanced deletion with exponential backoff
        print(f"Deleting {len(token_events)} token events with smart rate limiting...")

        base_delay = 2.0  # Start with 2 seconds
        max_delay = 60.0  # Maximum 60 seconds between attempts
        current_delay = base_delay
        successful_deletions = 0
        failed_deletions = 0

        for i, event in enumerate(token_events):
            attempt = 0
            max_attempts = 5

            while attempt < max_attempts:
                try:
                    print(
                        f"  Attempting to delete event {i + 1}/{len(token_events)} (attempt {attempt + 1})..."
                    )
                    await wallet.delete_token_event(event["id"])
                    successful_deletions += 1

                    # Success - reset delay to base level
                    current_delay = base_delay
                    print(f"  ✅ Deleted event {i + 1}/{len(token_events)}")
                    break

                except Exception as e:
                    error_msg = str(e).lower()

                    if (
                        "rate-limit" in error_msg
                        or "rate limit" in error_msg
                        or "too much" in error_msg
                    ):
                        attempt += 1
                        if attempt < max_attempts:
                            # Exponential backoff for rate limiting
                            current_delay = min(current_delay * 2, max_delay)
                            print(
                                f"  ⚠️  Rate limited, waiting {current_delay:.1f}s before retry {attempt + 1}/{max_attempts}"
                            )
                            await asyncio.sleep(current_delay)
                        else:
                            print(
                                f"  ❌ Failed to delete after {max_attempts} attempts: {e}"
                            )
                            failed_deletions += 1
                            # Still increase delay for next event
                            current_delay = min(current_delay * 1.5, max_delay)
                    else:
                        print(f"  ❌ Non-rate-limit error: {e}")
                        failed_deletions += 1
                        break

                # Wait between successful deletions too
                await asyncio.sleep(current_delay)

            # Progress update every 10 deletions
            if (i + 1) % 10 == 0:
                print(
                    f"  📊 Progress: {successful_deletions} successful, {failed_deletions} failed, {len(token_events) - i - 1} remaining"
                )

        print("\n📈 Deletion Summary:")
        print(f"  ✅ Successful: {successful_deletions}")
        print(f"  ❌ Failed: {failed_deletions}")
        print(f"  📊 Total: {len(token_events)}")

        # Wait for propagation before checking final balance
        print("\nWaiting for deletion propagation...")
        await asyncio.sleep(5)

        # Verify final state
        try:
            final_balance = await wallet.get_balance()
            print(f"Final balance: {final_balance} sats")

            if final_balance == 0:
                print("🎉 Wallet successfully cleared!")
            elif final_balance < balance:
                print(
                    f"✅ Partially cleared: reduced from {balance} to {final_balance} sats"
                )
            else:
                print("⚠️  Balance unchanged - deletions may not have propagated yet")
        except Exception as e:
            print(f"Could not verify final balance: {e}")


if __name__ == "__main__":
    asyncio.run(clear_wallet())
