"""Verify specific heuristic rules against Ethernaut contracts."""
import sys
sys.stdout.reconfigure(encoding='utf-8')
from heuristic_scanner import scan_file

# 1. CoinFlip - should catch blockhash
print("=" * 60)
print("1. CoinFlip - BLOCKHASH_RANDOMNESS")
results = scan_file(r'z:\Sentinal Engine\ethernaut\contracts\src\levels\CoinFlip.sol')
bh = [r for r in results if r.rule_id == 'BLOCKHASH_RANDOMNESS']
print(f'   Found: {len(bh)} (expected: >0)')
for r in bh:
    print(f'   Line {r.line_no}: {r.line_text[:80] if r.line_text else ""}')

# 2. AlienCodex - should catch array length underflow
print("\n2. AlienCodex - ARRAY_LENGTH_UNDERFLOW")
results = scan_file(r'z:\Sentinal Engine\ethernaut\contracts\src\levels\AlienCodex.sol')
au = [r for r in results if r.rule_id == 'ARRAY_LENGTH_UNDERFLOW']
print(f'   Found: {len(au)} (expected: >0)')
for r in au:
    print(f'   Line {r.line_no}: {r.line_text[:80] if r.line_text else ""}')

# 3. King - should catch transfer DoS
print("\n3. King - TRANSFER_DOSABLE_FALLBACK")
results = scan_file(r'z:\Sentinal Engine\ethernaut-standalone\King.sol')
td = [r for r in results if r.rule_id == 'TRANSFER_DOSABLE_FALLBACK']
print(f'   Found: {len(td)} (expected: >0)')
for r in td:
    print(f'   Line {r.line_no}: {r.line_text[:80] if r.line_text else ""}')

# 4. Force.sol - DIVIDE_BEFORE_MULTIPLY FP check (should be 0)
print("\n4. Force.sol - DIVIDE_BEFORE_MULTIPLY (FP check, expect 0)")
results = scan_file(r'z:\Sentinal Engine\ethernaut\contracts\src\levels\Force.sol')
dbm = [r for r in results if r.rule_id == 'DIVIDE_BEFORE_MULTIPLY']
print(f'   Found: {len(dbm)} (expected: 0)')

# 5. Fallout.sol - should be clean (no FP)
print("\n5. Fallout.sol - general check (expect minimal)")
results = scan_file(r'z:\Sentinal Engine\ethernaut\contracts\src\levels\Fallout.sol')
print(f'   Total findings: {len(results)}')
for r in results:
    print(f'   {r.rule_id}: Line {r.line_no}')

print("\n" + "=" * 60)
print("VERIFICATION COMPLETE")
