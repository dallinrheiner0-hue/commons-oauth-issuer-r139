"""Build-time content check; no network or database access."""
import hashlib
import json
from pathlib import Path

root=Path(__file__).resolve().parent
manifest=json.loads((root/'CONTENT.json').read_text())
for name,expected in manifest.items():
    if Path(name).name!=name or hashlib.sha256((root/name).read_bytes()).hexdigest()!=expected:
        raise SystemExit('Artifact content mismatch')
print('Frozen issuer content verified')
