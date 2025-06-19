#!/usr/bin/env python3
"""Example: Check wallet balance and proof details.

Shows current balance and proof state validation.
"""

import asyncio
import os
from dotenv import load_dotenv
from sixty_nuts.wallet import Wallet


async def check_wallet_status(wallet: Wallet):
    """Check and display detailed wallet status."""
    print("Fetching wallet state...\n")

    # Get wallet state with proof validation
    state = await wallet.fetch_wallet_state(check_proofs=True)

    print(f"💰 Total Balance: {state.balance} sats")
    print(f"📄 Total Proofs: {len(state.proofs)}")

    # Group proofs by mint
    proofs_by_mint: dict[str, list] = {}
    for proof in state.proofs:
        mint_url = proof.get("mint") or "unknown"
        if mint_url not in proofs_by_mint:
            proofs_by_mint[mint_url] = []
        proofs_by_mint[mint_url].append(proof)

    print(f"\n🏦 Mints in use: {len(proofs_by_mint)}")

    # Display breakdown by mint
    for mint_url, proofs in proofs_by_mint.items():
        mint_balance = sum(p["amount"] for p in proofs)
        print(f"\n  Mint: {mint_url}")
        print(f"  Balance: {mint_balance} sats")
        print(f"  Proofs: {len(proofs)}")

        # Show denomination breakdown
        denominations: dict[int, int] = {}
        for proof in proofs:
            amount = proof["amount"]
            denominations[amount] = denominations.get(amount, 0) + 1

        print("  Denominations:")
        for denom in sorted(denominations.keys()):
            count = denominations[denom]
            print(f"    {denom} sat: {count} proof(s)")

    # Check if any proofs are spent (shouldn't be any after validation)
    print(f"\n✅ All {len(state.proofs)} proofs are validated and unspent")


async def check_without_validation(wallet: Wallet):
    """Check wallet state without validating proofs (faster but less accurate)."""
    print("\n" + "=" * 50)
    print("Checking without proof validation (fast mode)...")

    # Get balance without checking proofs
    balance = await wallet.get_balance(check_proofs=False)
    print(f"\n💰 Reported Balance (unvalidated): {balance} sats")
    print("⚠️  Note: This may include spent proofs!")


async def check_balance_detailed(wallet: Wallet):
    """Check balance with detailed proof information."""
    print("Checking wallet balance...")

    # Get balance with proof validation
    try:
        balance_validated = await wallet.get_balance(check_proofs=True)
        print(f"\n✅ Validated balance: {balance_validated} sats")
        print("   (All proofs verified with mint)")
    except Exception as e:
        print(f"❌ Error validating proofs: {e}")
        balance_validated = None

    # Get balance without validation (faster)
    try:
        balance_quick = await wallet.get_balance(check_proofs=False)
        print(f"\n📊 Quick balance: {balance_quick} sats")
        print("   (From stored proofs, not validated)")
    except Exception as e:
        print(f"❌ Error getting balance: {e}")
        balance_quick = None

    # Get full wallet state
    try:
        state = await wallet.fetch_wallet_state(check_proofs=False)
        print("\n📝 Wallet details:")
        print(f"   Total proofs: {len(state.proofs)}")

        # Group proofs by amount
        amounts: dict[int, int] = {}
        for proof in state.proofs:
            amt = proof["amount"]
            amounts[amt] = amounts.get(amt, 0) + 1

        print("   Denominations:")
        for amt in sorted(amounts.keys(), reverse=True):
            print(f"     {amt:4d} sats × {amounts[amt]}")

    except Exception as e:
        print(f"❌ Error getting wallet state: {e}")


async def main():
    """Main example."""
    load_dotenv()
    nsec = os.getenv("NSEC")
    if not nsec:
        print("Error: NSEC environment variable not set. Please create a .env file.")
        return

    # Initialize wallet
    async with Wallet(
        nsec=nsec,
    ) as wallet:
        await check_wallet_status(wallet)
        await check_without_validation(wallet)
        await check_balance_detailed(wallet)


if __name__ == "__main__":
    asyncio.run(main())
