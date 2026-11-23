# guardian/ecosystems/__init__.py
# Ecosystem plugin registry – add new ecosystems here.

from guardian.ecosystems.npm import NpmPlugin

ECOSYSTEM_PLUGINS = [
    NpmPlugin(),
]
