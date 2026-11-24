#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="$DIR/fixtures/attack-demo"

rm -rf "$TARGET"
mkdir -p "$TARGET"
cd "$TARGET"

git init -b main
git config user.name "Guardian Demo"
git config user.email "demo@guardian.local"

# Commit 1: Clean base version
cat << 'EOF' > package.json
{
  "name": "attack-demo",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "3.10.1"
  }
}
EOF

cat << 'EOF' > package-lock.json
{
  "name": "attack-demo",
  "version": "1.0.0",
  "lockfileVersion": 2,
  "requires": true,
  "packages": {
    "": {
      "name": "attack-demo",
      "version": "1.0.0",
      "dependencies": {
        "lodash": "3.10.1"
      }
    },
    "node_modules/lodash": {
      "version": "3.10.1",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-3.10.1.tgz",
      "integrity": "sha512-sha512-originalhash123=="
    }
  }
}
EOF

git add package.json package-lock.json
git commit -m "Initial clean release"

# Commit 2: 3 planted attacks:
# 1. Typosquat package added with hasInstallScript: true (recats@1.0.0)
# 2. Major jump: lodash 3.10.1 -> 4.17.15 (vulnerable version)
# 3. Modified integrity hash on lodash
cat << 'EOF' > package.json
{
  "name": "attack-demo",
  "version": "1.1.0",
  "dependencies": {
    "lodash": "4.17.15",
    "recats": "1.0.0"
  }
}
EOF

cat << 'EOF' > package-lock.json
{
  "name": "attack-demo",
  "version": "1.1.0",
  "lockfileVersion": 2,
  "requires": true,
  "packages": {
    "": {
      "name": "attack-demo",
      "version": "1.1.0",
      "dependencies": {
        "lodash": "4.17.15",
        "recats": "1.0.0"
      }
    },
    "node_modules/lodash": {
      "version": "4.17.15",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz",
      "integrity": "sha512-sha512-TAMPERED_MODIFIED_HASH_999=="
    },
    "node_modules/recats": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/recats/-/recats-1.0.0.tgz",
      "integrity": "sha512-PLANTED_TYPOSQUAT_HASH==",
      "hasInstallScript": true
    }
  }
}
EOF

git add package.json package-lock.json
git commit -m "Add recats and bump lodash"

echo "Created attack-demo git history at $TARGET"
