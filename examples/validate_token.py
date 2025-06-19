#!/usr/bin/env python3
"""Validate a Cashu token and check which proofs are spent."""

import asyncio
import os
import sys
from dotenv import load_dotenv
from sixty_nuts.wallet import Wallet


async def validate_token(token: str):
    """Validate a Cashu token and check spent status of each proof."""
    print("🔍 Validating Cashu token...")
    print("=" * 50)

    # Create a temporary wallet just for parsing
    async with Wallet(
        nsec="nsec1vl83hlk8ltz85002gr7qr8mxmsaf8ny8nee95z75vaygetnuvzuqqp5lrx",
    ) as wallet:
        try:
            # Parse the token
            mint_url, unit, proofs = wallet._parse_cashu_token(token)

            print("\n📊 Token details:")
            print(f"   Mint: {mint_url}")
            print(f"   Unit: {unit}")
            print(f"   Proofs: {len(proofs)}")
            print(f"   Total value: {sum(p['amount'] for p in proofs)} {unit}")

            # Group by keyset
            keysets: dict[str, list] = {}
            for proof in proofs:
                keyset_id = proof["id"]
                if keyset_id not in keysets:
                    keysets[keyset_id] = []
                keysets[keyset_id].append(proof)

            print("\n🔑 Keysets found:")
            for keyset_id, keyset_proofs in keysets.items():
                total = sum(p["amount"] for p in keyset_proofs)
                print(f"   {keyset_id}: {len(keyset_proofs)} proofs, {total} {unit}")

            # Check proof states
            print("\n🔄 Checking proof states with mint...")
            mint = wallet._get_mint(mint_url)

            spent_count = 0
            unspent_count = 0
            error_count = 0

            # Check in batches
            batch_size = 100
            for i in range(0, len(proofs), batch_size):
                batch = proofs[i : i + batch_size]

                try:
                    # Compute Y values for this batch
                    y_values = wallet._compute_proof_y_values(batch)
                    state_response = await mint.check_state(Ys=y_values)

                    for j, proof in enumerate(batch):
                        if j < len(state_response.get("states", [])):
                            state_info = state_response["states"][j]
                            state = state_info.get("state", "UNKNOWN")

                            if state == "SPENT":
                                spent_count += 1
                            elif state == "UNSPENT":
                                unspent_count += 1
                            else:
                                error_count += 1

                            # Show first few individual results
                            if i + j < 5:  # Show first 5 proofs
                                print(
                                    f"   Proof {i + j + 1}: {proof['amount']} {unit} - {state}"
                                )
                        else:
                            error_count += 1

                except Exception as e:
                    print(f"   Error checking batch {i // batch_size + 1}: {str(e)}")
                    error_count += len(batch)

            if len(proofs) > 5:
                print(f"   ... and {len(proofs) - 5} more")

            # Summary
            print("\n📈 Validation Summary:")
            print(f"   Total proofs: {len(proofs)}")
            print(f"   ✅ Unspent: {unspent_count} proofs")
            print(f"   ❌ Spent: {spent_count} proofs")
            if error_count > 0:
                print(f"   ⚠️  Errors: {error_count} proofs")

            if spent_count == len(proofs):
                print("\n❌ All proofs in this token are already spent!")
            elif spent_count > 0:
                print(
                    f"\n⚠️  Warning: {spent_count} out of {len(proofs)} proofs are already spent."
                )
                print("   The token will fail to redeem due to spent proofs.")
            elif unspent_count == len(proofs):
                print("\n✅ All proofs are unspent and should be redeemable!")

            # Check if keysets are active
            print("\n🔐 Checking keyset status...")
            try:
                keys_resp = await mint.get_keys()
                active_keysets = {ks["id"] for ks in keys_resp.get("keysets", [])}

                for keyset_id in keysets.keys():
                    if keyset_id in active_keysets:
                        print(f"   ✅ Keyset {keyset_id} is active")
                    else:
                        print(f"   ❌ Keyset {keyset_id} is NOT active (obsolete)")
                        print("      This keyset cannot be redeemed normally!")
            except Exception as e:
                print(f"   Error checking keysets: {str(e)}")

        except Exception as e:
            print(f"\n❌ Error parsing token: {str(e)}")
            return


async def main():
    """Main function."""
    if len(sys.argv) < 2:
        print("Usage: python validate_token.py <token_or_file>")
        print("\nProvide either:")
        print("  - A Cashu token string (starting with 'cashuA...')")
        print("  - A filename containing a Cashu token")
        sys.exit(1)

    token_input = sys.argv[1]

    # Check if it's a file or a token string
    if token_input.startswith("cashuA"):
        token = token_input
    else:
        # Try to read from file
        try:
            with open(token_input, "r") as f:
                token = f.read().strip()
        except FileNotFoundError:
            print(f"❌ File not found: {token_input}")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error reading file: {e}")
            sys.exit(1)

    await validate_token(token)


if __name__ == "__main__":
    asyncio.run(main())
