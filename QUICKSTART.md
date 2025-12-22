# 🚀 The Sentinel Engine - Quick Start Guide

## Zero-to-Audit in 3 Commands

### **1. Build the Engine**
```bash
docker build -t sentinel-engine .
```
**Expected output:**
```
[+] Building 120.5s (15/15) FINISHED
 => [internal] load build definition
 => [internal] load .dockerignore
 => [5/10] RUN pip install slither-analyzer solc-select...
 => [8/10] RUN curl -L https://foundry.paradigm.xyz | bash
 => [10/10] RUN python3 -c "import slither; print('✓ Slither OK')"
✓ Sentinel Engine initialized
```

**⏱️ Build time:** ~3-5 minutes (one-time setup)  
**📦 Image size:** ~600MB

---

### **2. Run Your First Scan**

**Method A: Full Pipeline (Orchestrator)**
```bash
# Scan all contracts in current directory
docker run --rm -v $(pwd):/scan sentinel-engine --target /scan
```

**Method B: Single Module (Liar Detector)**
```bash
# Check one specific file for intent mismatches
docker run --rm -v $(pwd):/scan sentinel-engine python3 intent_check.py /scan/contracts/MyVault.sol
```

**Method C: Threat Intelligence**
```bash
# Auto-detect EVM/Solana and query vulnerability databases
docker run --rm -v $(pwd):/scan sentinel-engine python3 threat_intel.py /scan/contracts/Token.sol
```

---

### **3. Get Your Report**

**Output locations:**
- **Console:** Immediate findings printed to terminal
- **File:** `ACTION_PLAN_YYYYMMDD_HHMMSS.md` in your scanned directory

**Example report structure:**
```markdown
# 🚨 SECURITY AUDIT REPORT

## Executive Summary
- **Critical:** 2 findings
- **High:** 5 findings  
- **Medium:** 12 findings

## Heuristic Scanner
[CRITICAL] UNCHECKED_EXTERNAL_CALL (Line 142)
  • External call without return value check
  • 💡 FIX: Wrap in require() or check success boolean

## Liar Detector
[MISMATCH] Line 67: emergencyWithdraw
  • Comment says "admin" but function is public with NO modifier
  • 💡 FIX: Add onlyOwner modifier

## Threat Intelligence
Found 3 similar exploits in Code4rena:
  • ERC4626 Inflation Attack ($50K bounty)
  • Oracle Staleness Bug ($120K bounty)
```

---

## 📚 Common Workflows

### **For Bug Bounty Hunters**
```bash
# 1. Quick heuristic scan (finds 90% of high-value bugs)
docker-compose run --rm heuristic-scan

# 2. Check for intent mismatches (catches "forgot modifier" bugs)
docker-compose run --rm liar-detector /scan/contracts/Vault.sol

# 3. Query historical exploits
docker-compose run --rm threat-intel /scan/contracts/Vault.sol
```

### **For Professional Auditors**
```bash
# Full pipeline with all modules enabled
docker run --rm -v $(pwd):/scan sentinel-engine \
  --target /scan \
  --heuristic \
  --symbolic \
  --fuzz InvariantTest
```

### **For Learning/Education (TokenAudit YouTube)**
```bash
# Interactive shell to explore tools
docker run --rm -it -v $(pwd):/scan sentinel-engine /bin/bash

# Inside container:
root@abc:/app# python3 intent_check.py /scan/examples/VulnerableVault.sol
root@abc:/app# python3 access_matrix.py /scan/examples/Token.sol
root@abc:/app# python3 threat_intel.py /scan/examples/AMM.sol
```

---

## 🛠️ Troubleshooting

### **Issue: "Cannot find contract file"**
```bash
# Make sure you're mounting the correct directory
# Windows PowerShell:
docker run --rm -v ${PWD}:/scan sentinel-engine --target /scan

# Linux/Mac:
docker run --rm -v $(pwd):/scan sentinel-engine --target /scan
```

### **Issue: "Slither failed to compile"**
This is normal if:
- Contract uses newer Solidity version (add to Dockerfile: `RUN solc-select install 0.8.25`)
- Missing dependencies (run from Foundry/Hardhat project root)

**Workaround:**
```bash
# Use modules that don't need compilation
docker-compose run --rm heuristic-scan      # Regex-based (always works)
docker-compose run --rm liar-detector       # Comment parsing (always works)
docker-compose run --rm threat-intel        # API-based (always works)
```

### **Issue: Docker build fails on Foundry**
If `foundryup` times out during build:
```dockerfile
# In Dockerfile, add timeout to RUN command:
RUN curl -L https://foundry.paradigm.xyz | bash || true
RUN timeout 300 /root/.foundry/bin/foundryup || echo "Foundry install partial"
```

---

## 🎯 Next Steps

1. **Customize for your needs:**
   - Edit `heuristic_scanner.py` to add custom vulnerability patterns
   - Edit `intent_check.py` to add project-specific trust keywords
   - Edit `docker-compose.yml` to set default contract paths

2. **Integrate into CI/CD:**
   ```yaml
   # .github/workflows/security.yml
   - name: Security Scan
     run: |
       docker build -t sentinel .
       docker run --rm -v $PWD:/scan sentinel --target /scan
   ```

3. **Deploy Forta Watchtower:**
   - See README "Phase 5: The Watchtower" section
   - Convert your invariant tests to runtime monitors

4. **Contribute:**
   - Add new heuristic patterns
   - Improve threat intelligence sources
   - Submit PRs to CyberShield Austin / TokenAudit

---

**🎓 Educational Use:** Perfect for TokenAudit YouTube tutorials  
**💼 Professional Use:** CyberShield Austin client deliverables  
**🏆 Bug Bounties:** Immunefi/Code4rena hunting toolkit

**Questions?** Open an issue or reach out to TokenAudit community.
