"""One-time plan revision helper; does not modify issues or product code."""
from pathlib import Path
p=Path('docs/planning/build_task_catalog.py')
s=p.read_text()
if '# Accepted review-1 and integration-challenger corrections.' in s:
    raise SystemExit('Revision already applied; rerender with build_task_catalog.py and enrich_catalog.py')
insert='''# Accepted review-1 and integration-challenger corrections.
updates={
'E02': {'scope': 'Offline baseline-analysis schema and human-run baseline recipe; analyze existing captures if available. Missing live measurements remain separate.', 'acceptance': 'Package completion is not baseline measurement. Missing comparison bars quantified improvement claims but permits absolute qualification.'},
'P01': {'scope_extra': ' Define typed secret-store, source-session, command and latency contracts with ephemeral test implementations.'},
'S02': {'title': 'Qualify negotiated source-codec profiles', 'scope_extra': ' Derive mandatory decoder set from pinned Spotify/AirPlay negotiated formats; keep optional internal transport codec separate.', 'acceptance_extra': ' Unsupported negotiated formats fail explicitly; no Vorbis-only provider assumption.'},
'S03': {'deps_extra':['U01']}, 'A02': {'deps_extra':['U01']}, 'T02': {'deps_extra':['U01']},
'X03': {'deps':['E01','P04','P03','N02']},
'U01': {'scope_extra':' Separate credential namespaces and calibration; define replacement/revocation, permissions, secret-redacted errors, bounded capacity/write rates and crash consistency. Persistence does not imply encryption or hardware-backed custody.'},
'Q01': {'deps_extra':['D04']},
'Q02': {'deps':['Q01','D04'], 'acceptance_extra':' No-FEC is valid for baseline. Repeat with each enabled optional profile.'},
'Q03': {'deps':['Q02','U03','E02'], 'acceptance_extra':' Baseline Spotify, volume, joins, source restart, loss envelope and rollback. Declare thresholds before execution. Report absolute vs comparative evidence separately.'},
'Q04': {'deps':['Q03','T02','X02','X04','A02','V02','L01'], 'acceptance_extra':' Gateway and FEC qualification are conditional on enabled profiles; optional absence neither closes nor blocks native requirements.'},
'N06': {'scope_extra':' Implement only if N05 admits a measured FEC profile; no-FEC outcome keeps this optional capability deferred.'}
}
revised=[]
for key,title,deps,scope,accept in rows:
 u=updates.get(key,{})
 revised.append((key,u.get('title',title),u.get('deps',deps)+u.get('deps_extra',[]),u.get('scope',scope)+u.get('scope_extra',''),u.get('acceptance',accept)+u.get('acceptance_extra','')))
rows=revised
rows.append(('X04','Implement and qualify Alexa voice-to-Spotify routing',['X01','X02','S03','G01'],'Supported music-destination/account-routing integration with explicit provider admission and target group selection.','Offline directives do not qualify music routing. Require documented supported mechanism and later owner-operated utterance-to-selected-group playback receipt; unavailable provider admission remains blocked, not silently replaced by volume control.'))
'''
s=s.replace('tasks=[]',insert+'\ntasks=[]',1)
s=s.replace("Status: planning draft; no implementation or hardware deployment authorized by this artifact.","Status: reviewed implementation plan; task creation is complete only with Beads receipts. This artifact does not authorize hardware deployment.")
s=s.replace('parts=[header]',"""header+='''\n## Milestones and canonical task keys\n\nM1 is the offline mixed-generation Spotify candidate: Q01/Q02 execution evidence and Q03/U03 human handoff.\nHardware qualification is separately pending until authorized external receipts exist.\nM2 is the full native integration campaign Q04/Q05; no optional gateway/FEC/local-voice prerequisite.\nN05/N06, T03 and X03 are retained optional branches with profile-specific qualification.\nThe canonical task keys below own completion; R01-R15 and INT-001-018 are mapped design packages, not duplicate issues.\nThe full runtime and integration specifications follow the task catalog in this document.\n\n'''
parts=[header]""")
s=s.replace("Path('docs/SLIM_SPEAKER_PLAN.md').write_text('\\n'.join(parts))", """for companion in ('SLIM_RUNTIME_DESIGN.md','SLIM_INTEGRATIONS_DESIGN.md'):
 parts.append('\\n# Detailed specification: '+companion+'\\n\\n'+Path('docs',companion).read_text())
Path('docs/SLIM_SPEAKER_PLAN.md').write_text('\\n'.join(parts))""")
p.write_text(s)
# Companion correction agreed by its reviewer.
p=Path('docs/SLIM_RUNTIME_DESIGN.md'); s=p.read_text().replace('Depends on R12 through R14 and the selected recovery policy from R09.','Baseline depends on R12/R13; R14 and R09 are required only for enabled video/recovery profiles.'); p.write_text(s)
