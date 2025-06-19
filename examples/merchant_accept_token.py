import asyncio
import os
import sys
from dotenv import load_dotenv
from sixty_nuts.wallet import Wallet


async def accept_payment(token: str, trusted_mint: str):
    """Accept a Cashu token and swap it to trusted mint."""
    load_dotenv()
    nsec = os.getenv("NSEC")
    if not nsec:
        print("Error: NSEC environment variable not set. Please create a .env file.")
        return

    async with Wallet(
        nsec=nsec,
        mint_urls=[trusted_mint],
    ) as wallet:
        # Parse token to show original amount
        source_mint, token_unit, proofs = wallet._parse_cashu_token(token)
        original_amount = sum(p["amount"] for p in proofs)

        print(f"Token from: {source_mint}")
        print(f"Amount: {original_amount} {token_unit}")

        # Redeem automatically swaps to trusted mint
        amount, received_unit = await wallet.redeem(token)

        fees = original_amount - amount
        print(f"\nReceived: {amount} {received_unit}")
        if fees > 0:
            print(f"Lightning fees: {fees} {received_unit}")

        return amount, received_unit


async def main():
    """Main example."""
    TRUSTED_MINT = "https://mint.minibits.cash/Bitcoin"

    if len(sys.argv) < 2:
        print("Usage: python merchant_accept_token.py <cashu_token>")
        return

    token = sys.argv[1]

    try:
        amount, unit = await accept_payment(token, TRUSTED_MINT)
        print("\n✅ Payment successful!")
    except Exception as e:
        print(f"\n❌ Payment failed: {e}")


if __name__ == "__main__":
    asyncio.run(main())
