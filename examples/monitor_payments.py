import asyncio
import os
import time
from dotenv import load_dotenv
from sixty_nuts.wallet import Wallet


async def monitor_payment(wallet: Wallet, amount: int, description: str = ""):
    """Create invoice and monitor for payment."""
    print(f"Creating invoice for {amount} sats...")

    # Create invoice with async monitoring
    invoice, payment_task = await wallet.mint_async(amount, timeout=300)

    print("\n" + "=" * 60)
    print(f"⚡ Lightning Invoice: {invoice}")
    print("=" * 60)
    print(f"\n💵 Amount: {amount} sats")
    print("⏱️  Timeout: 5 minutes")
    print("\nWaiting for payment...")

    # Show progress while waiting
    start_time = time.time()
    dots = 0

    while not payment_task.done():
        elapsed = int(time.time() - start_time)
        minutes = elapsed // 60
        seconds = elapsed % 60

        # Create animated waiting indicator
        dots = (dots + 1) % 4
        waiting_text = "." * dots + " " * (3 - dots)

        print(
            f"\r⏳ Waiting{waiting_text} [{minutes:02d}:{seconds:02d}]",
            end="",
            flush=True,
        )

        await asyncio.sleep(0.5)

    # Check if payment was received
    paid = await payment_task
    print()  # New line after progress indicator

    if paid:
        print("\n✅ Payment received!")

        # Show new balance
        balance = await wallet.get_balance()
        print(f"💰 New balance: {balance} sats")

        return True
    else:
        print("\n❌ Payment timed out!")
        return False


async def process_multiple_payments(wallet: Wallet):
    """Example of processing multiple payments concurrently."""
    print("\nExample: Processing multiple payments concurrently\n")

    # Create multiple invoices
    payments = [
        ("Coffee", 5000),
        ("Sandwich", 8000),
        ("Dessert", 3000),
    ]

    tasks = []

    for item, amount in payments:
        print(f"Creating invoice for {item} ({amount} sats)...")
        invoice, task = await wallet.mint_async(amount, timeout=600)
        tasks.append((item, amount, invoice, task))
        print(f"  Invoice: {invoice[:50]}...")

    print("\nMonitoring all payments (10 minute timeout)...")

    # Wait for any payment to complete
    while tasks:
        # Check which payments are done
        for item, amount, invoice, task in tasks[:]:
            if task.done():
                paid = await task
                if paid:
                    print(f"\n✅ {item} paid! ({amount} sats)")
                else:
                    print(f"\n❌ {item} payment expired")
                tasks.remove((item, amount, invoice, task))

        if tasks:
            # Show status
            print(f"\r⏳ Waiting for {len(tasks)} payment(s)...", end="", flush=True)
            await asyncio.sleep(1)

    print("\n\nAll payments processed!")
    balance = await wallet.get_balance()
    print(f"💰 Final balance: {balance} sats")


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
        # Example 1: Monitor single payment
        print("Example 1: Single payment monitoring")
        await monitor_payment(wallet, 21, "Test payment")

        # Example 2: Multiple concurrent payments (commented out for demo)
        # await process_multiple_payments(wallet)


if __name__ == "__main__":
    asyncio.run(main())
