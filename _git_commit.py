import subprocess, os, sys

base = r'z:\Sentinal Engine\sentinel-engine'
os.chdir(base)

files = [
    'orchestrator.py', 'license_manager.py', 'report_generator.py',
    'logger.py', 'state_manager.py', 'signature_updater.py',
    'rag_engine.py', 'plugin_manager.py', 'pipeline_generator.py',
    'heuristic_scanner.py', 'red_team_scan.py', 'attack_graph.py',
    'exploit_generator.py', 'history_scanner.py', 'fingerprint_scanner.py',
    'supply_chain_check.py', 'fork_logic_checks.py', 'access_matrix.py',
    'intent_check.py', 'upgrade_diff.py', 'solana_analyzer.py',
    'solana_intel.py', 'threat_intel.py', 'embeddings.py', 'visualizer.py',
    'idl_validator.py', 'protocol_db.py', 'healthcheck.py',
    'knowledge_fetcher.py', 'http_utils.py', 'gui.py',
    'aderyn_wrapper.py', 'medusa_wrapper.py', 'symbolic_wrapper.py',
    'fuzz_wrapper.py', 'exceptions.py', 'config_loader.py',
]

lines = []

r = subprocess.run(['git', 'add'] + files, capture_output=True, text=True, cwd=base)
lines.append(f'ADD rc: {r.returncode}')
if r.stdout: lines.append('ADD stdout: ' + r.stdout[:500])
if r.stderr: lines.append('ADD stderr: ' + r.stderr[:500])

r2 = subprocess.run(
    ['git', 'commit', '-m', 'refactor: rebrand core Python modules to Counterscarp Engine'],
    capture_output=True, text=True, cwd=base
)
lines.append(f'COMMIT rc: {r2.returncode}')
if r2.stdout: lines.append('COMMIT stdout: ' + r2.stdout[:500])
if r2.stderr: lines.append('COMMIT stderr: ' + r2.stderr[:500])

r3 = subprocess.run(['git', 'log', '--oneline', '-5'], capture_output=True, text=True, cwd=base)
lines.append(f'LOG rc: {r3.returncode}')
if r3.stdout: lines.append('LOG: ' + r3.stdout)

result_path = os.path.join(base, '_git_result.txt')
with open(result_path, 'w', encoding='utf-8') as f:
    f.write('\n'.join(lines) + '\n')

print('\n'.join(lines))
