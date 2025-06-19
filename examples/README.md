# Sixty Nuts Examples

This directory contains example scripts demonstrating various features of the sixty_nuts library. Each example serves as both a learning resource and an integration test.

## Prerequisites

Before running the examples, you need to install the dependencies:

1. Install [uv](https://github.com/astral-sh/uv) (a fast Python package manager):

   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

2. Install dependencies using uv:

   ```bash
   # From the project root directory
   uv sync
   ```

This will install all required dependencies including the sixty_nuts library itself.

## Configuration

To run these examples, you need to set up your Nostr private key (`nsec`) as an environment variable. This is a crucial security measure to avoid hardcoding sensitive information.

1.  **Create a `.env` file:** Copy the example environment file:
    ```bash
    cp .env.example .env
    ```

2.  **Edit `.env`:** Open the newly created `.env` file and replace `your_nostr_private_key_here` with your actual `nsec` (Nostr private key).
    ```dotenv
    NSEC=nsec1...
    ```
    **Important:** Do not commit your `.env` file to version control!

## Basic Operations

### mint_and_send.py

Shows the basic flow of minting tokens from Lightning and sending Cashu tokens.

```bash
python mint_and_send.py
```

### check_balance_and_proofs.py

Check wallet balance and see detailed breakdown by mint and denomination.

```bash
python check_balance_and_proofs.py
```

### send_to_lightning_address.py

Send tokens to any Lightning Address (LNURL).

```bash
python send_to_lightning_address.py user@getalby.com 1000
```

### clear_wallet.py

Melt all tokens back to Lightning, clearing the wallet.

```bash
python clear_wallet.py
```

## Advanced Token Management

### redeem_token.py

Simple token redemption into your wallet.

```bash
# Redeem a token
python redeem_token.py cashuAey...

# Redeem from file
python redeem_token.py $(cat token.txt)
```

### split_tokens.py

Split tokens into specific denominations for privacy or payment preparation.

```bash
# Split into multiple amounts
python split_tokens.py 100 50 25 10 5

# Prepare exact amount token
python split_tokens.py 137
```

### validate_token.py

Validate tokens before accepting them - essential for merchants.

```bash
# Simple validation
python validate_token.py cashuAey...

# Merchant acceptance flow
python validate_token.py merchant cashuAey... 1000

# Batch validation
python validate_token.py batch token1 token2 token3
```

## Payment Processing

### merchant_accept_token.py

Accept tokens from any mint and automatically swap to your trusted mint.

```bash
python merchant_accept_token.py cashuAey...
```

### monitor_payments.py

Create Lightning invoices and monitor for payment in real-time.

```bash
python monitor_payments.py
```

### one_off_redeem.py

Use temporary wallets for one-off token redemptions without storing keys.

```bash
# Single redemption
python one_off_redeem.py cashuAey... user@getalby.com

# Batch redemption
python one_off_redeem.py user@getalby.com token1 token2 token3
```

## Multi-Mint Operations

### multi_mint_operations.py

Work with multiple mints, check balances per mint, and move funds between mints.

```bash
python multi_mint_operations.py
```

### auto_multi_mint_melt.py

Demonstrates the enhanced melt functionality that automatically consolidates proofs from multiple mints when no single mint has enough balance to pay a Lightning invoice.

```bash
python auto_multi_mint_melt.py
```

Features:

- Automatic invoice amount detection
- Total balance verification across all mints
- Smart mint selection based on balance
- Automatic proof consolidation when needed
- Transparent fee handling

This is particularly useful when your funds are distributed across multiple mints and you need to pay an invoice larger than any single mint's balance.

## Wallet Maintenance & Backup

### refresh_proofs.py

Refresh all proofs for privacy - swaps old proofs for new ones at the mint.

```bash
# Refresh with default backup directory
python refresh_proofs.py

# Specify custom backup directory
python refresh_proofs.py /path/to/backups
```

Features:

- Backs up all proofs before refreshing
- Consolidates small proofs into larger ones
- Maintains privacy by breaking proof chains
- Creates recovery instructions if needed
- Automatically handles mint limits (batches large sets of proofs)

### restore_proofs.py

Restore proofs from a backup file created by refresh_proofs.py.

```bash
python restore_proofs.py proof_backups/proofs_backup_20240115_123456.json
```

### export_all_tokens.py

Export all wallet proofs as standard Cashu tokens for backup or transfer.

```bash
python export_all_tokens.py
```

Creates timestamped token files that can be:

- Imported into any Cashu wallet
- Used as cold storage backup
- Shared for payment

**⚠️ Security Note**: Exported tokens contain actual money. Keep them secure!

### diagnose_duplicates.py

Diagnose duplicate proofs and balance inconsistencies in your wallet.

```bash
python diagnose_duplicates.py
```

Features:

- Identifies duplicate proofs stored in multiple events
- Shows actual vs reported balance
- Validates proofs with mint
- Provides clear recommendations

### cleanup_spent_proofs.py

Remove spent proofs and duplicates from the wallet.

```bash
python cleanup_spent_proofs.py
```

Features:

- Validates all proofs with the mint
- Identifies and removes spent proofs
- Cleans up duplicate entries
- Shows before/after balance comparison

### force_wallet_cleanup.py

Force a complete wallet cleanup when the state is severely corrupted.

```bash
python force_wallet_cleanup.py
```

Features:

- Deletes ALL token events (including duplicates)
- Validates all unique proofs with the mint
- Republishes only valid proofs in clean events
- Use as last resort when other cleanup methods fail

### cleanup_with_pow.py

Cleanup wallet with automatic Proof-of-Work support for relays that require it.

```bash
python cleanup_with_pow.py
```

Features:

- Automatically mines PoW when relays require it
- Handles 28+ bit difficulty requirements
- Shows progress during mining
- Cleans up spent proofs efficiently

### test_pow.py

Test the Proof-of-Work implementation.

```bash
python test_pow.py
```

Features:

- Tests PoW mining at different difficulties
- Verifies PoW correctness
- Tests relay integration with PoW
- Shows mining performance

## Common Patterns

### Error Handling

All examples include proper error handling and user-friendly messages.

### Async/Await

All operations use Python's async/await for efficient concurrent operations.

### Context Managers

Examples use `async with Wallet(...)` to ensure proper resource cleanup.

### Type Hints

Full type annotations for better IDE support and code clarity.

## Testing with Examples

These examples can be used as integration tests:

```bash
# Run all examples (requires funded wallet)
for script in *.py; do
    echo "Running $script..."
    python "$script"
done
```

## Troubleshooting

### Inconsistent Balances

If you see different balances when running `check_balance_and_proofs.py`:

1. Run `diagnose_duplicates.py` to identify the issue
2. Run `cleanup_spent_proofs.py` to remove spent/duplicate proofs
3. Run `refresh_proofs.py` to consolidate remaining proofs

If the problem persists:

Run `force_wallet_cleanup.py` as a last resort to completely rebuild the wallet state

### Mint Errors (422)

If you get a "422" error about too many inputs:

- The mint has a limit (usually 1000) on inputs per request
- The `refresh_proofs.py` script automatically handles this by batching
- For manual operations, split large proof sets into smaller batches

### Relay Errors (PoW Required)

If you see "pow: 28 bits needed" errors:

- The relay requires Proof-of-Work to prevent spam
- Use `cleanup_with_pow.py` which automatically mines PoW
- PoW mining can take 10-60 seconds for 28 bits
- The implementation uses multiple CPU cores for faster mining

## Notes

- All examples use the same test wallet key for consistency
- Replace the `nsec` with your own for production use
- Some examples require command-line arguments - run without args to see usage
- Examples demonstrate best practices for the library
