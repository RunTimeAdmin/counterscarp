"""Check Slither results from the scan."""
import sys
import io
if isinstance(sys.stdout, io.TextIOWrapper):
    sys.stdout.reconfigure(encoding='utf-8')
from red_team_scan import run_slither, filter_vulnerabilities

try:
    raw = run_slither(r'z:\Sentinal Engine\ethernaut\contracts\src\levels')
    filtered = filter_vulnerabilities(raw)
    print(f"Slither raw success: {raw.get('success', 'N/A')}")
    print(f"Slither raw detectors: {len(raw.get('results', {}).get('detectors', []))}")
    print(f"Filtered vulnerabilities: {len(filtered)}")
    by_impact: dict[str, int] = {}
    for f in filtered:
        impact = f.get('impact', 'Unknown')
        by_impact[impact] = by_impact.get(impact, 0) + 1
    print(f"By severity: {by_impact}")
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
