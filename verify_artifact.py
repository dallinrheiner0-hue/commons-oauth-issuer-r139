"""Build-time content check; no network or database access."""
import hashlib
import json
from pathlib import Path

root=Path(__file__).resolve().parent
manifest=json.loads((root/'CONTENT.json').read_text())
for name,expected in manifest.items():
    if Path(name).name!=name or hashlib.sha256((root/name).read_bytes()).hexdigest()!=expected:
        raise SystemExit('Artifact content mismatch')
actual={p.name for p in root.iterdir() if p.is_file()}
if actual != set(manifest)|{'CONTENT.json'}:
    raise SystemExit('Unexpected release file')
print('Frozen diagnostic content verified')
