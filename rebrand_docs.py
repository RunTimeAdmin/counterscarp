"""Rebrand all documentation from Garrison to Counterscarp."""
import os

# Brand mapping - order matters (longer strings first to avoid partial replacements)
mappings = [
    ('app.garrisonsec.com', 'app.counterscarp.io'),
    ('garrisonsec.com', 'counterscarp.io'),
    ('support@garrisonsec.com', 'contact@counterscarp.io'),
    ('help@protocol14019.com', 'contact@counterscarp.io'),
    ('github.com/RunTimeAdmin/garrison-engine', 'github.com/RunTimeAdmin/counterscarp'),
    ('pypi.org/project/garrison-engine', 'pypi.org/project/counterscarp-engine'),
    ('GARRISON_PRO_LICENSE', 'COUNTERSCARP_PRO_LICENSE'),
    ('GARRISON_LOG_LEVEL', 'COUNTERSCARP_LOG_LEVEL'),
    ('GARRISON_LOG_FORMAT', 'COUNTERSCARP_LOG_FORMAT'),
    ('GARRISON_LOG_FILE', 'COUNTERSCARP_LOG_FILE'),
    ('GARRISON_UPLOAD_DIR', 'COUNTERSCARP_UPLOAD_DIR'),
    ('GARRISON_RESULTS_DIR', 'COUNTERSCARP_RESULTS_DIR'),
    ('garrison_engine', 'counterscarp_engine'),
    ('Garrison Security Engine', 'Counterscarp Security Engine'),
    ('Garrison Engine', 'Counterscarp Engine'),
    ('garrison-engine', 'counterscarp-engine'),
    ('garrison-pr.toml', 'counterscarp-pr.toml'),
    ('garrison-audit.toml', 'counterscarp-audit.toml'),
    ('garrison-bounty.toml', 'counterscarp-bounty.toml'),
    ('garrison.toml', 'counterscarp.toml'),
    ('.garrison/', '.counterscarp/'),
    ('garrison-generate-pipeline', 'counterscarp-generate-pipeline'),
    ('garrison-security', 'counterscarp-security'),
    ('garrison-scan', 'counterscarp-scan'),
    ('GarrisonConfig', 'CounterscarfConfig'),
    ('GarrisonError', 'CounterscarfError'),
    ('GarrisonConfigError', 'CounterscarfConfigError'),
    ('GarrisonAnalysisError', 'CounterscarfAnalysisError'),
    ('GarrisonAPIError', 'CounterscarfAPIError'),
    ('GarrisonReportError', 'CounterscarfReportError'),
    ('GarrisonToolNotFoundError', 'CounterscarfToolNotFoundError'),
    ('GarrisonValidationError', 'CounterscarfValidationError'),
    ('GarrisonTimeoutError', 'CounterscarfTimeoutError'),
    # Generic garrison -> counterscarp (must be last)
    ('garrison', 'counterscarp'),
    ('Garrison', 'Counterscarp'),
]

files = [
    'README.md',
    'QUICKSTART.md',
    'CHANGELOG.md',
    'ARCHITECTURE.md',
    'CONTRIBUTING.md',
    'SECURITY.md',
    'docs/CLI_REFERENCE.md',
    'docs/CONFIGURATION.md',
    'docs/CONTRIBUTING_SIGNATURES.md',
    'docs/DEPLOYMENT.md',
    'docs/GETTING_STARTED.md',
    'docs/PLUGIN_DEVELOPMENT.md',
    'docs/REPORT_FORMATS.md',
    'docs/RULES_CATALOG.md',
    'docs/WEB_APP_GUIDE.md',
    '.github/PYPI_TRUSTED_PUBLISHER.md',
]

base = os.path.dirname(os.path.abspath(__file__))

for rel_path in files:
    path = os.path.join(base, rel_path)
    if not os.path.exists(path):
        print(f'MISSING: {rel_path}')
        continue
    with open(path, 'r', encoding='utf-8') as fh:
        content = fh.read()
    original = content
    for old, new in mappings:
        content = content.replace(old, new)
    if content != original:
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write(content)
        print(f'Updated: {rel_path}')
    else:
        print(f'No changes: {rel_path}')

print('Done')
