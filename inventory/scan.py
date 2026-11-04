import socket,time,json,urllib.request,xml.etree.ElementTree as E,pathlib,datetime
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(.5)
msg='M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 2\r\nST: urn:schemas-upnp-org:device:ZonePlayer:1\r\n\r\n'
urls=set()
for _ in range(3):
 s.sendto(msg.encode(),('239.255.255.250',1900)); end=time.time()+3
 while time.time()<end:
  try:
   data,addr=s.recvfrom(65535)
   for line in data.decode(errors='replace').splitlines():
    if line.lower().startswith('location:'): urls.add(line.split(':',1)[1].strip())
  except socket.timeout: pass
rows=[]
for i,url in enumerate(sorted(urls)):
 try:
  raw=urllib.request.urlopen(url,timeout=3).read();pathlib.Path(f'inventory/device-{i}.xml').write_bytes(raw)
  root=E.fromstring(raw); fields={el.tag.split('}')[-1]:el.text for el in root.iter() if len(el)==0}
  rows.append({'url':url,'fields':fields})
 except Exception as e: rows.append({'url':url,'error':str(e)})
pathlib.Path('inventory/devices.json').write_text(json.dumps({'observed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'method':'SSDP ZonePlayer M-SEARCH, three rounds; description GET','devices':rows},indent=2))
for r in rows: print(r['url'],json.dumps({k:v for k,v in r.get('fields',{}).items() if k in ['roomName','modelName','modelNumber','hardwareVersion','softwareVersion','serialNum','UDN']}))
