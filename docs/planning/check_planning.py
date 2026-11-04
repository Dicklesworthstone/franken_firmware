"""Read-only offline planning consistency check; prints JSON and never invokes br.

Snapshot list output contains dependency counts, not edges. Exact edge equality
therefore uses the local .beads/issues.jsonl export; neither input is live proof.
Run render_planning.py and refresh the snapshot/export separately before checking.
"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / 'docs/planning'


def check():
    errors = []

    def require(condition, message):
        if not condition:
            errors.append(message)

    def read(name):
        return json.loads((HERE / name).read_text())

    def indexed(rows, field, label):
        result = {row[field]: row for row in rows}
        require(len(result) == len(rows), f'{label}: duplicate {field}')
        return result

    catalog = indexed(read('task-catalog.json'), 'key', 'catalog')
    manifest = indexed(read('bead-manifest.json'), 'key', 'manifest')
    mapping = read('bead-map.json')
    snapshot = read('beads-snapshot.json')
    rows = snapshot['issues'] if isinstance(snapshot, dict) else snapshot
    if isinstance(snapshot, dict):
        require(not snapshot.get('has_more', False), 'snapshot is paginated/incomplete')
        require(snapshot.get('offset', 0) == 0, 'snapshot starts after first issue')
        require(snapshot.get('total', len(rows)) == len(rows), 'snapshot total differs from row count')
    stored = indexed(rows, 'id', 'snapshot')
    exported = indexed([
        json.loads(line) for line in (ROOT / '.beads/issues.jsonl').read_text().splitlines()
        if line.strip()
    ], 'id', 'export')
    require(set(catalog) == set(manifest) == set(mapping), 'catalog/manifest/map key sets differ')
    require(len(set(mapping.values())) == len(mapping), 'map assigns one issue to multiple tasks')
    colors, cycles = {}, []

    def visit(key, trail):
        if colors.get(key) == 1:
            cycles.append(trail[trail.index(key):] + [key])
            return
        if colors.get(key) == 2 or key not in catalog:
            return
        colors[key] = 1
        for dep in catalog[key]['deps']:
            visit(dep, trail + [key])
        colors[key] = 2

    for key in catalog:
        visit(key, [])
    require(not cycles, f'cycles detected: {cycles}')
    counts = dict(description_matches=0, title_matches=0, dependency_set_matches=0,
                  snapshot_dependency_count_matches=0, manifest_matches=0)
    actual_edges = 0
    packages = set()
    ready = []
    for key, task in catalog.items():
        deps = task['deps']
        require(len(deps) == len(set(deps)), f'{key}: duplicate canonical dependency')
        require(all(dep in catalog and dep in mapping for dep in deps), f'{key}: unknown dependency')
        packages.update(task['design_packages'])
        item = manifest.get(key)
        issue_id = mapping.get(key)
        if item is None or issue_id not in stored or issue_id not in exported:
            errors.append(f'{key}: missing manifest, snapshot or exported issue')
            continue
        snap, export = stored[issue_id], exported[issue_id]
        body_path = (ROOT / item['body']).resolve()
        if not body_path.is_relative_to(HERE / 'bead-bodies'):
            errors.append(f'{key}: body path outside canonical body directory')
            continue
        body = body_path.read_text()
        manifest_ok = (item['title'] == task['title'] and item['deps'] == deps
                       and item['body'] == f'docs/planning/bead-bodies/{key}.md')
        require(manifest_ok, f'{key}: manifest differs from catalog')
        counts['manifest_matches'] += manifest_ok
        for label, value in [('Scope', task['scope']), ('Acceptance', task['acceptance']),
                             ('Owned outputs', task['output_path']), ('Evidence', task['evidence_status'])]:
            require(f'\n{label}: {value}\n' in body, f'{key}: stale body {label}')
        require(body.endswith('Detailed implementation and validation contract:\n\n' + task['detailed_contract']),
                f'{key}: stale detailed contract')
        body_ok = body == snap['description'] == export['description']
        title_ok = snap['title'] == export['title'] == key + ': ' + task['title']
        require(body_ok, f'{key}: complete body differs from snapshot/export')
        require(title_ok, f'{key}: title differs from snapshot/export')
        counts['description_matches'] += body_ok
        counts['title_matches'] += title_ok
        blocking = [d['depends_on_id'] for d in export.get('dependencies', []) if d['type'] == 'blocks']
        expected = {mapping[dep] for dep in deps if dep in mapping}
        edge_ok = set(blocking) == expected and len(blocking) == len(set(blocking))
        require(edge_ok, f'{key}: exported blocking edges differ')
        counts['dependency_set_matches'] += edge_ok
        actual_edges += len(blocking)
        count_ok = snap.get('dependency_count') == len(deps)
        require(count_ok, f'{key}: snapshot dependency count differs')
        counts['snapshot_dependency_count_matches'] += count_ok
        if snap['status'] == 'open' and not deps:
            ready.append({'id': issue_id, 'title': snap['title']})
    return {
        'status': 'pass' if not errors else 'fail', 'tasks': len(catalog),
        'blocking_edges': actual_edges, 'expected_blocking_edges': sum(len(t['deps']) for t in catalog.values()),
        'cycles': len(cycles), **counts, 'mapped_design_packages': len(packages),
        'root_open_tasks': ready,
        'plan_sha256': hashlib.sha256((ROOT / 'docs/SLIM_SPEAKER_PLAN.md').read_bytes()).hexdigest(),
        'audit_scope': 'Offline canonical catalog/manifest/map/body versus saved snapshot and local issue export; exact edges from export, dependency counts from snapshot. No live br query or mutation; root_open_tasks is not a full readiness computation.',
        'implementation_executed': False, 'hardware_accessed': False,
        'provider_accessed': False, 'errors': errors,
    }


if __name__ == '__main__':
    try:
        result = check()
    except (OSError, ValueError, KeyError, TypeError) as exc:
        result = {'status': 'fail', 'errors': [f'{type(exc).__name__}: {exc}']}
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['status'] == 'pass' else 1)
