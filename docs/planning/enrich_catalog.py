"""Idempotently render crosswalk and self-contained issue specifications from plan sources."""
import json,re
from pathlib import Path
root=Path(__file__).resolve().parents[2]
paths={name:root/'docs'/name for name in ('SLIM_RUNTIME_DESIGN.md','SLIM_INTEGRATIONS_DESIGN.md')}
cross={
'R01':['E01','E03'],'R02':['P02'],'R03':['E06','P03'],'R04':['E04'],'R05':['P04'],'R06':['D01','D02'],'R07':['N01','N02'],'R08':['N04'],'R09':['N05','N06'],'R10':['N03','D03','P02'],'R11':['G01','G02'],'R12':['D04','Q01'],'R13':['G03'],'R14':['V01','V02'],'R15':['Q02','Q03','Q04'],
'INT-001':['E01','E06','P01'],'INT-002':['P01','N02','G01'],'INT-003':['S01','E06'],'INT-004':['S01','S03'],'INT-005':['S03','Q02','Q03'],'INT-006':['A01'],'INT-007':['A02'],'INT-008':['V01','V02'],'INT-009':['V02'],'INT-010':['T01'],'INT-011':['T02','T03','U01'],'INT-012':['X01'],'INT-013':['X02','X04'],'INT-014':['L01'],'INT-015':['X03'],'INT-016':['G03'],'INT-017':['G01','G02','G03','Q01','Q04'],'INT-018':['Q04','Q05']}
sections={}
for name,p in paths.items():
 text=p.read_text(); sections[name]=[x for x in re.split(r'(?=^## )',text,flags=re.M) if x.startswith('## ')]
tasks=json.loads((root/'docs/planning/task-catalog.json').read_text()); by={t['key']:t for t in tasks}
explicit_sections=json.loads((root/'docs/planning/section-map.json').read_text())
assert set(explicit_sections)==set(by), 'Every canonical task needs an explicit section map'
for t in tasks:
 key=t['key']; t['design_packages']=[k for k,v in cross.items() if key in v]
 selected=[]
 for ref in explicit_sections[key]:
  matches=[section for section in sections[ref['file']] if section.splitlines()[0]=='## '+ref['heading']]
  if len(matches)!=1:
   raise ValueError(f"Missing or ambiguous section for {key}: {ref}")
  selected.append(matches[0])
 t['detailed_contract']='\n'.join(selected)+'\n'+(root/'docs/planning/QUALIFICATION_TARGETS.md').read_text()
 t['inputs']=[f"{d}: {by[d]['title']} — {by[d]['scope']}" for d in t['deps']]
 t['output_path']=f"docs/contracts/{key.lower()}.md plus focused implementation/fixtures in the corresponding workspace crate; qualify paths during P01"
 t['evidence_status']='Offline implementation and synthetic qualification only; provider and physical claims require separate authorized receipts.'
(root/'docs/planning/task-catalog.json').write_text(json.dumps(tasks,indent=2)+'\n')
lines=['# Design-package crosswalk','', 'Canonical catalog keys own completion. Copy the mapped detailed contracts into Beads; do not create duplicate R/INT issues.','', '| Design package | Canonical tasks |','|---|---|']
lines += [f"| {k} | {', '.join(v)} |" for k,v in cross.items()]
(root/'docs/planning/design-crosswalk.md').write_text('\n'.join(lines)+'\n')
p=root/'docs/SLIM_SPEAKER_PLAN.md'; s=p.read_text(); marker='\n# Design-package crosswalk\n'; s=s.split(marker)[0]; s+='\n'+(root/'docs/planning/design-crosswalk.md').read_text()+'\n'+(root/'docs/planning/QUALIFICATION_TARGETS.md').read_text(); p.write_text(s)
assert len(cross)==33
assert all(k in by for vals in cross.values() for k in vals)
print(f'{len(tasks)} tasks enriched, {len(cross)} companion packages mapped')
