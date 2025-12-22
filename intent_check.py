import re
import argparse
import sys
from typing import List, Dict

# CONFIGURATION
# Keywords in comments that imply restriction/safety
TRUST_KEYWORDS = ["admin", "owner", "restrict", "internal", "private", "lock", "withdraw", "protected", "authorized", "secure"]

# Modifiers that enforce restriction
AUTH_MODIFIERS = ["onlyOwner", "onlyRole", "auth", "nonReentrant", "lock", "whenNotPaused", "onlyGovernance"]

def analyze_intent(filepath: str):
    """
    Detects mismatches between developer intent (NatSpec comments) and implementation (modifiers).
    Catches psychological security bugs where devs *thought* they secured something but didn't.
    """
    print("\n" + "="*60)
    print(f" 🤥 LIAR DETECTOR (Comment vs. Code Mismatch)")
    print("="*60)
    
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    issues = []
    
    # We use a window approach: look at comments immediately preceding a function
    comment_buffer = []
    
    for i, line in enumerate(lines):
        clean_line = line.strip()
        
        # 1. Capture NatSpec/Comments
        if clean_line.startswith("//") or clean_line.startswith("/*") or clean_line.startswith("*"):
            comment_buffer.append(clean_line.lower())
            continue
            
        # 2. Detect Function Definition
        if clean_line.startswith("function "):
            # Analyze the accumulated comments
            combined_comment = " ".join(comment_buffer)
            
            # Check for Trust Words in comments
            found_trust_word = next((w for w in TRUST_KEYWORDS if w in combined_comment), None)
            
            if found_trust_word:
                # We expect protections in the function definition
                has_auth = any(mod in clean_line for mod in AUTH_MODIFIERS)
                is_internal = "internal" in clean_line or "private" in clean_line
                
                # THE LOGIC: 
                # If comment says "Admin" AND function is "Public/External" AND No Auth Modifier -> LIAR!
                if not has_auth and not is_internal:
                    issues.append({
                        "line": i + 1,
                        "function": clean_line.split("(")[0].replace("function ", ""),
                        "trigger_word": found_trust_word,
                        "comment": combined_comment[-100:] # Last 100 chars
                    })
            
            # Reset buffer after function found
            comment_buffer = []
        
        # Clear buffer if we hit a blank line or struct (context break)
        elif clean_line == "" or clean_line.startswith("struct") or clean_line.startswith("contract"):
            comment_buffer = []

    # REPORTING
    print(f"\n[*] Analyzed {len(lines)} lines in {filepath}")
    print(f"[*] Detected {len(issues)} intent/implementation mismatches\n")
    
    if not issues:
        print("✅ CLEAN. Code appears to match developer intent.")
        print("   All restricted functions have proper access controls.")
    else:
        print("\033[91m⚠️  CRITICAL: Developer intent does NOT match implementation!\033[0m")
        print("   These functions claim restriction but are publicly accessible:\n")
        
        for issue in issues:
            print(f"\033[91m[MISMATCH] Line {issue['line']}: {issue['function']}\033[0m")
            print(f"  • Comment implies: '{issue['trigger_word']}'")
            print(f"  • Code reality:    Public/External with NO detected modifiers.")
            print(f"  • Snippet:         ...{issue['comment']}...")
            print(f"\n  \033[93m💡 FIX: Add modifier (onlyOwner, onlyRole, etc.) or change visibility to internal.\033[0m")
            print("-" * 60)
    
    print("\n" + "="*60)
    return issues

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="🤥 Liar Detector - Scan for Intent/Implementation mismatches in Solidity contracts"
    )
    parser.add_argument("file", help="The .sol file to analyze")
    args = parser.parse_args()
    
    analyze_intent(args.file)
