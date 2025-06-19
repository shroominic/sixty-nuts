import asyncio
import os
import sys
from dotenv import load_dotenv
from sixty_nuts.wallet import Wallet


async def just_send():
    """Sends Cashu tokens from the wallet and prints the resulting token string."""
    load_dotenv()
    nsec = os.getenv("NSEC")
    if not nsec:
        print("Error: NSEC environment variable not set. Please create a .env file.")
        sys.exit(1)

    if len(sys.argv) < 2:
        print("Usage: python just_send.py <amount_to_send>")
        print("Example: python just_send.py 100")
        sys.exit(1)

    try:
        amount_to_send = int(sys.argv[1])
        if amount_to_send <= 0:
            raise ValueError("Amount to send must be a positive integer.")
    except ValueError as e:
        print(f"Error: Invalid amount provided. {e}")
        sys.exit(1)

    async with Wallet(
        nsec=nsec,
    ) as wallet:
        current_balance = await wallet.get_balance()
        print(f"Current wallet balance: {current_balance} sats")

        if current_balance < amount_to_send:
            print(f"Error: Insufficient balance. You want to send {amount_to_send} sats, but only have {current_balance} sats.")
            return

        print(f"Attempting to send {amount_to_send} sats from your wallet...")
        try:
            token = await wallet.send(amount_to_send)
            print("\n----------------------------------------------------")
            print("         CASHU TOKEN GENERATED SUCCESSFULLY         ")
            print("----------------------------------------------------")
            print(f"Token (for {amount_to_send} sats):\n{token}")
            print("----------------------------------------------------")
            print("\nRemember to provide this token to the recipient.")
            print("The balance in your wallet has been reduced.")

            final_balance = await wallet.get_balance()
            print(f"New wallet balance: {final_balance} sats")

        except Exception as e:
            print(f"Error sending tokens: {e}")

if __name__ == "__main__":
    asyncio.run(just_send())
