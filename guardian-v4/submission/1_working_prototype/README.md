# Software Supply Chain Guardian - Quick Start

## 1. Setup
```bash
pip install -r requirements.txt
cp .env.example .env
```

## 2. Launch Streamlit UI
```bash
streamlit run guardian/app.py
```

## 3. CLI Commands
```bash
# Scan a local folder or public GitHub URL
python -m guardian.cli scan fixtures/demo-app --demo-cache
python -m guardian.cli scan https://github.com/lodash/lodash --no-ai

# Scan with change analysis against a git ref
python -m guardian.cli scan fixtures/attack-demo --since HEAD~1 --demo-cache

# Run evaluation & selfcheck
python -m guardian.cli selfcheck
python -m guardian.cli eval

# Verify a finding's claims against the ledger
python -m guardian.cli verify F-001 --run out/demo-app-run
```
