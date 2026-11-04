"""Pure full-body renderer. Never mutates the issue database."""
import json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
folder = ROOT / 'docs/planning/bead-bodies'
folder.mkdir(exist_ok=True)
tasks = json.loads((ROOT / 'docs/planning/task-catalog.json').read_text())
by = {task['key']: task for task in tasks}
def closure(key, stack=()):
    if key in stack:
        raise ValueError(f'Dependency cycle: {stack} -> {key}')
    return {key}.union(*(closure(dep, stack + (key,)) for dep in by[key]['deps']))
for key in by:
    closure(key)
first = closure('Q03')
manifest = []
for t in tasks:
    inputs = '\n'.join('- ' + item for item in t['inputs']) or '- Owner scope, sanitized inventory and existing evidence registry.'
    body = f"""# {t['key']}: {t['title']}

Goal: reliable slim retained-kernel Rust audio across mixed generations; native integrations remain required.

Scope: {t['scope']}

Why: preserve bounded protected rendering while retiring unrelated service complexity.

Inputs:
{inputs}

Owned outputs: {t['output_path']}

Acceptance: {t['acceptance']}

Evidence: {t['evidence_status']}

Authority: offline engineering or validation of externally supplied receipts only. No live device commands, firmware installation or account enrollment here. Follow AGENTS.md; public fixtures contain no site identifiers or secrets. Application/protocol/DSP forbid unsafe; platform exceptions require explicit invariants and review. The owner permits upstream Franken library adaptations; record their exact revisions and tests.

Failure/closure: distinguish completed design/probe from feature admission. T04 separately gates native tailnet development; Q06 and X05 gate external qualification. Required features cannot be removed by disabling implementation flags. Record exact build/profile/command/denominator. Each task owns focused unit/property/contract tests and bounded redacted failure diagnostics.

Mapped design packages: {', '.join(t['design_packages']) or 'canonical standalone task'}.

Detailed implementation and validation contract:

{t['detailed_contract']}"""
    path = folder / (t['key'] + '.md')
    path.write_text(body)
    manifest.append({'key': t['key'], 'title': t['title'], 'deps': t['deps'], 'body': str(path.relative_to(ROOT)), 'priority': 1 if t['key'] in first else 2})
(ROOT / 'docs/planning/bead-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(f'Rendered {len(manifest)} complete issue bodies; no br mutations')
