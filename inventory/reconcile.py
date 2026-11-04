import pathlib,json,os,urllib.request,xml.etree.ElementTree as E,datetime
p=pathlib.Path(__file__).parent
jpath = pathlib.Path(os.environ.get('FSONOS_DEVICES_JSON', p/'.devices.local.json'))
j=json.load(open(jpath));now=datetime.datetime.now(datetime.timezone.utc).isoformat()
peer_xml = p/'.peer-extra-device.local.xml'
if peer_xml.exists():
    f={e.tag.split('}')[-1]:e.text for e in E.parse(peer_xml).iter() if len(e)==0}
else:
    f={}
peer_reported = os.environ.get('FSONOS_PEER_IP', '')  # owner-local; never commit real IPs
if peer_reported and not any(r['fields'].get('serialNum')==f.get('serialNum') for r in j['devices']):
    u = f'http://{peer_reported}:1400/xml/device_description.xml'
    f = ET.fromstring(urllib.request.urlopen(u, timeout=10).read())
    j['devices'].append({'url':u,'fields':{c.tag.split('}')[-1]:(c.text or '').strip() for c in f.find('{urn:schemas-upnp-org:device-1-0}device')},'status':{},'observed_at':now,'published_hardware_profile':json.load(open(p/'hardware-profiles.json'))['S5']})
lines=['# Reconciled Sonos inventory','',f'Reconciled {now}. {len(j["devices"])} distinct serial numbers. Capacities below are device-reported nominal MB, not measured available RAM.','', '| Room | Model | IP | Series | RAM / flash MB | Hardware |','|---|---|---|---|---|---|']
records=[]
for r in j['devices']:
 f=r['fields']; cap={k:f.get(k) for k in ['seriesid','memory','flash']};r['device_reported_capacity']=cap
 lines.append('| '+' | '.join([r.get('status',{}).get('ZoneName',f.get('roomName','?')),f['modelNumber'],r['url'].split('/')[2],str(cap['seriesid']),str(cap['memory'])+' / '+str(cap['flash']),f['hardwareVersion']])+' |')
 records.append({'content':'Correction/supplement to earlier Sonos hardware inventory: '+json.dumps({'serial':f['serialNum'],'model':f['modelNumber'],'url':r['url'],'hardware':f['hardwareVersion'],'reported':cap})+'. These fields were present in device_description.xml; supersede earlier claims of unknown capacity and generic teardown capacity for this owned unit. CPU remains a separate published-hardware inference.','level':'semantic','kind':'fact','tags':['sonos','inventory','correction'],'source':(p/'devices.json').resolve().as_uri()})
j['reconciled_at']=now;jpath.write_text(json.dumps(j,indent=2));(p/'INVENTORY.md').write_text('\n'.join(lines)+'\n');print('wrote',jpath,'and INVENTORY.md (sanitize INVENTORY.md before committing: strip IPs/rooms)')
