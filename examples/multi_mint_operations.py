import asyncio
import os
from dotenv import load_dotenv
from sixty_nuts.wallet import Wallet


# Popular Cashu mints for demonstration
MINTS = {
    "minibits": "https://mint.minibits.cash/Bitcoin",
    "21mint": "https://21mint.me",
    "stablenut": "https://stablenut.cashu.network",
}


async def check_multi_mint_balance(wallet: Wallet):
    """Check balance across all configured mints."""
    print("Checking balances across all mints...\n")

    state = await wallet.fetch_wallet_state(check_proofs=True)

    # Group by mint
    mint_balances: dict[str, int] = {}
    for proof in state.proofs:
        mint_url = proof.get("mint") or "unknown"
        mint_balances[mint_url] = mint_balances.get(mint_url, 0) + proof["amount"]

    print("💰 Balance by mint:")
    total = 0
    for mint_url, balance in mint_balances.items():
        print(f"  {mint_url}: {balance} sats")
        total += balance

    if not mint_balances:
        print("  No balance in any mint")

    print(f"\n📊 Total across all mints: {total} sats")
    print(f"🏦 Configured mints: {len(wallet.mint_urls)}")

    return mint_balances


async def move_between_mints(
    wallet: Wallet,
    amount: int,
    from_mint: str | None = None,
    to_mint: str | None = None,
):
    """Move funds from one mint to another."""
    # Use defaults if not specified
    if from_mint is None:
        from_mint = wallet.mint_urls[0] if wallet.mint_urls else None
    if to_mint is None:
        to_mint = wallet.mint_urls[1] if len(wallet.mint_urls) > 1 else None

    if not from_mint or not to_mint or from_mint == to_mint:
        print("❌ Need two different mints for transfer")
        return

    print(f"\n💸 Moving {amount} sats:")
    print(f"   From: {from_mint}")
    print(f"   To: {to_mint}")

    # Get current balances
    state = await wallet.fetch_wallet_state(check_proofs=True)

    # Find proofs from source mint
    source_proofs = [p for p in state.proofs if p.get("mint") == from_mint]

    source_balance = sum(p["amount"] for p in source_proofs)
    if source_balance < amount:
        print(f"❌ Insufficient balance at source mint: {source_balance} sats")
        return

    try:
        # Create token from source mint
        # Note: This is a simplified approach - in production you'd want
        # to select specific proofs from the source mint
        print("\nCreating token from source mint...")
        token = await wallet.send(amount)

        # Swap to target mint
        print("Swapping to target mint...")
        received, unit = await wallet.swap_mints(token, target_mint=to_mint)

        print(f"✅ Successfully moved {received} {unit}")
        print(f"   (Fees: {amount - received} {unit})")

    except Exception as e:
        print(f"❌ Transfer failed: {e}")


async def add_new_mint(wallet: Wallet, mint_url: str):
    """Add a new mint to the wallet."""
    print(f"\n➕ Adding new mint: {mint_url}")

    if mint_url not in wallet.mint_urls:
        wallet.mint_urls.append(mint_url)

        # Update wallet event with new mint
        await wallet.create_wallet_event()
        print("✅ Mint added and wallet updated")
    else:
        print("ℹ️  Mint already in wallet")


async def consolidate_to_primary_mint(wallet: Wallet):
    """Consolidate all funds to the primary (first) mint."""
    print("\n🔄 Consolidating all funds to primary mint...")

    if not wallet.mint_urls:
        print("❌ No mints configured")
        return

    primary_mint = wallet.mint_urls[0]
    print(f"Primary mint: {primary_mint}")

    # Get current state
    state = await wallet.fetch_wallet_state(check_proofs=True)

    # Group proofs by mint
    proofs_by_mint: dict[str, list] = {}
    for proof in state.proofs:
        mint_url = proof.get("mint") or primary_mint
        if mint_url not in proofs_by_mint:
            proofs_by_mint[mint_url] = []
        proofs_by_mint[mint_url].append(proof)

    # Move funds from each non-primary mint
    total_moved = 0
    for mint_url, proofs in proofs_by_mint.items():
        if mint_url == primary_mint:
            continue

        balance = sum(p["amount"] for p in proofs)
        if balance > 0:
            print(f"\n  Moving {balance} sats from {mint_url}")
            try:
                # Create token with all proofs from this mint
                token = wallet._serialize_proofs_for_token(proofs, mint_url)

                # Swap to primary mint
                received, unit = await wallet.swap_mints(
                    token, target_mint=primary_mint
                )

                print(f"  ✅ Moved {received} {unit}")
                total_moved += received

            except Exception as e:
                print(f"  ❌ Failed: {e}")

    if total_moved > 0:
        print(f"\n✅ Total consolidated: {total_moved} sats")
    else:
        print("\nℹ️  No funds to consolidate")


async def main():
    """Main example."""
    load_dotenv()
    nsec = os.getenv("NSEC")
    if not nsec:
        print("Error: NSEC environment variable not set. Please create a .env file.")
        return

    # Initialize wallet with multiple mints
    async with Wallet(
        nsec=nsec,
        mint_urls=[MINTS["minibits"], MINTS["lnbits"]],
    ) as wallet:
        # Check balances across mints
        balances = await check_multi_mint_balance(wallet)

        # Example: Move funds between mints (if we have balance)
        if any(balance > 100 for balance in balances.values()):
            await move_between_mints(wallet, 100)

        # Example: Add a new mint
        # await add_new_mint(wallet, MINTS["mutiny"])

        # Example: Consolidate all funds to primary mint
        # await consolidate_to_primary_mint(wallet)


if __name__ == "__main__":
    asyncio.run(main())
