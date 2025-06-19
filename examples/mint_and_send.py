import asyncio
import os
from dotenv import load_dotenv
from sixty_nuts.wallet import Wallet


async def main():
    load_dotenv()
    nsec = os.getenv("NSEC")
    if not nsec:
        print("Error: NSEC environment variable not set. Please create a .env file.")
        return

    async with Wallet(
        nsec=nsec
    ) as wallet:
        # Check balance
        balance = await wallet.get_balance()
        print(f"Balance: {balance} sats")

        # Mint 10 sats
        invoice, confirmation = await wallet.mint_async(10, timeout=600)
        print(f"\nPay this invoice:\n{invoice}")

        await confirmation
        print("\n✓ Payment received!")

        # Send 5 sats
        if await wallet.get_balance() >= 5:
            token = await wallet.send(5)
            print(f"\nCashu token:\n{token}")

            balance = await wallet.get_balance()
            print(f"\nRemaining balance: {balance} sats")
        else:
            print("Insufficient balance")


if __name__ == "__main__":
    asyncio.run(main())
