import asyncio
import os
import sys
from dotenv import load_dotenv
from sixty_nuts.wallet import Wallet, WalletError


async def send_to_address(wallet: Wallet, address: str, amount: int):
    """Send tokens to a Lightning Address."""
    print(f"Sending {amount} sats to {address}...")

    try:
        # Send to Lightning Address (handles LNURL automatically)
        actual_paid = await wallet.send_to_lnurl(address, amount)

        print("✅ Successfully sent!")
        print(f"   Total paid (including fees): {actual_paid} sats")

        # Wait a moment for state to settle before showing balance
        await asyncio.sleep(1)

        # Show remaining balance
        balance = await wallet.get_balance()
        print(f"\nRemaining balance: {balance} sats")

    except WalletError as e:
        if "Insufficient balance" in str(e):
            print(f"❌ {e}")
            print("\n💡 Tip: Lightning payments require mint fees (typically 1 sat)")
            print("   Make sure your balance is > amount you want to send")
        else:
            print(f"❌ Failed to send: {e}")
        raise
    except Exception as e:
        print(f"❌ Failed to send: {e}")
        raise


async def main():
    """Main example."""
    if len(sys.argv) < 3:
        print("Usage: python send_to_lightning_address.py <lightning_address> <amount>")
        print("Example: python send_to_lightning_address.py user@getalby.com 100")
        print("\n💡 Note: Lightning payments require fees (typically 1 sat)")
        print("   Your balance must be > amount you want to send")
        return

    address = sys.argv[1]
    amount = int(sys.argv[2])

    load_dotenv()
    nsec = os.getenv("NSEC")
    if not nsec:
        print("Error: NSEC environment variable not set. Please create a .env file.")
        return

    # Initialize wallet
    async with Wallet(
        nsec=nsec,
    ) as wallet:
        # Check balance first
        balance = await wallet.get_balance()
        print(f"Current balance: {balance} sats")

        if balance < amount:
            print(f"❌ Insufficient balance! Need {amount}, have {balance}")
            return

        # Warn if balance is tight
        if balance == amount:
            print("⚠️  Warning: Balance equals send amount. This will fail due to fees.")
            print(f"   Consider sending {amount - 1} sats instead.")
            return
        elif balance == amount + 1:
            print(f"💡 Note: You have exactly enough for {amount} sats + 1 sat fee")

        await send_to_address(wallet, address, amount)


if __name__ == "__main__":
    asyncio.run(main())
