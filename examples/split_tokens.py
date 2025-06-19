import asyncio
import os
import sys
from dotenv import load_dotenv
from sixty_nuts.wallet import Wallet


async def split_tokens(wallet: Wallet, denominations: list[int]):
    """Split wallet balance into specific denominations."""
    # Check current balance
    balance = await wallet.get_balance()
    total_requested = sum(denominations)

    print(f"Current balance: {balance} sats")
    print(f"Requested split: {denominations} (total: {total_requested} sats)")

    if total_requested > balance:
        print(f"❌ Insufficient balance! Need {total_requested}, have {balance}")
        return None

    # First, create a token with the exact amount we want to split
    print(f"\nCreating token for {total_requested} sats...")
    token = await wallet.send(total_requested)

    # Now redeem it back, which will give us optimal denominations
    print("Redeeming with split...")
    amount, unit = await wallet.redeem(token)

    print(f"✅ Successfully split {amount} {unit} into optimal denominations")

    # Show the resulting denomination breakdown
    state = await wallet.fetch_wallet_state(check_proofs=False)
    denominations_count: dict[int, int] = {}

    for proof in state.proofs:
        amount = proof["amount"]
        denominations_count[amount] = denominations_count.get(amount, 0) + 1

    print("\nResulting denominations:")
    for denom in sorted(denominations_count.keys(), reverse=True):
        count = denominations_count[denom]
        print(f"  {denom} sat: {count} token(s)")

    return token


async def prepare_exact_amount(wallet: Wallet, amount: int):
    """Prepare a token with exact amount for payment."""
    print(f"\nPreparing exact {amount} sat token...")

    try:
        token = await wallet.send(amount)
        print(f"✅ Token ready: {token}")
        return token
    except Exception as e:
        print(f"❌ Failed to prepare token: {e}")
        return None


async def main():
    """Main example."""
    if len(sys.argv) < 2:
        print("Usage: python split_tokens.py <amount> [amount2] [amount2] ...")
        print("Example: python split_tokens.py 100 50 25 10 5")
        print("\nOr to prepare exact amount:")
        print("Usage: python split_tokens.py <amount>")
        print("Example: python split_tokens.py 137")
        return

    amounts = [int(arg) for arg in sys.argv[1:]]

    load_dotenv()
    nsec = os.getenv("NSEC")
    if not nsec:
        print("Error: NSEC environment variable not set. Please create a .env file.")
        return

    # Initialize wallet
    async with Wallet(
        nsec=nsec,
    ) as wallet:
        if len(amounts) == 1:
            # Prepare exact amount
            await prepare_exact_amount(wallet, amounts[0])
        else:
            # Split into multiple denominations
            await split_tokens(wallet, amounts)


if __name__ == "__main__":
    asyncio.run(main())
