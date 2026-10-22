#pragma once
// Dashboard HTML for the C3 AdBlocker web UI, kept in its own header so the
// Arduino IDE preprocessor doesn't choke on the inlined markup (issue #6).
// Plain HTML/JS, no frameworks. Tabs: Overview / DNS / Lists / Devices / System (location.hash).

const char PAGE[] PROGMEM = R"HTML(<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>C3 AdBlock</title><style>
body{font:14px system-ui,sans-serif;margin:0;background:#0d1117;color:#c9d1d9}
header{background:#161b22;padding:10px 16px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
h1{margin:0;font-size:18px;flex:1;min-width:200px}h1 span{color:#3fb950;font-size:14px;font-weight:500}
nav{display:flex;gap:2px;padding:0 12px;background:#161b22;border-bottom:1px solid #30363d;overflow-x:auto}
nav a{color:#8b949e;text-decoration:none;padding:9px 12px;border-bottom:2px solid transparent;white-space:nowrap}
nav a.on{color:#c9d1d9;border-color:#f78166}
.wrap{padding:16px;max-width:1000px;margin:auto}section{display:none}section.on{display:block}
.cards{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:14px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 16px;flex:1;min-width:130px}
.card .v{font-size:22px;font-weight:600}.card .l{color:#8b949e;font-size:12px}
.box{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 14px;margin-bottom:14px;line-height:1.6}
.tw{overflow-x:auto;margin-bottom:14px}table{width:100%;border-collapse:collapse;background:#161b22;border-radius:8px;overflow:hidden}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid #21262d;font-size:13px}th{background:#21262d;color:#8b949e}
.b{color:#f85149}.a{color:#3fb950}td.r,th.r{text-align:right;white-space:nowrap}.m{color:#8b949e;font-size:12px}.tag{background:#30363d;border-radius:4px;padding:1px 6px;font-size:11px}
button{background:#21262d;color:#c9d1d9;border:1px solid #30363d;border-radius:5px;padding:5px 10px;cursor:pointer}
button:hover{background:#30363d}button.p{background:#238636;border-color:#2ea043;color:#fff}
input,select{background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:5px;padding:6px}
h2{font-size:13px;color:#8b949e;margin:18px 0 8px;letter-spacing:.5px}
.row{display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:8px}
.warn{display:none;background:#3b1d1d;border:1px solid #f85149;color:#ffb3ae;border-radius:8px;padding:10px 14px;margin-bottom:12px;font-size:13px}
</style></head><body>
<header><h1>🛡️ C3 AdBlock <span id=host></span></h1><span id=blockdot>🛡️</span><b id=blockstate data-on=1>Blocking active</b>
<select id=pausedur><option value=30>30s</option><option value=300 selected>5 min</option><option value=1800>30 min</option><option value=0>until I re-enable</option></select>
<button id=pausebtn onclick=togglePause()>Pause</button></header>
<nav><a href=#overview>Overview</a><a href=#dns>DNS</a><a href=#lists>Lists</a><a href=#devices>Devices</a><a href=#system>System</a></nav>
<div class=wrap>
<div id=credwarn class=warn>⚠️ <b>Default credentials in use.</b> WEB_PASS/OTA_PASS in <code>secrets.h</code> are still the placeholder values &mdash; anyone can read them in the public repo. Set real values and reflash.</div>
<div id=uwarn class=warn></div>

<section id=overview>
<div class=cards id=sys></div>
<div class=box><b>DNS servers:</b> <span id=chain></span><br><span class=m>Change them on the DNS tab.</span></div>
<div class=box><b>Blocklist:</b> <span id=listsum></span><br><span class=m>Details, custom rules and the domain tester are on the Lists tab.</span></div>
</section>

<section id=dns>
<h2>FILTERS <span class=m>(checked in this order for every lookup)</span></h2><div class=box>
<div class=row><label><input type=checkbox id=lston onchange=setList(this.checked)> <b>1. Local blocklist</b></label><span id=lstinfo class=m></span></div>
<div class=row><b>2. Your custom blocks and exceptions</b><span id=cusinfo class=m></span></div>
<div class=row><b>3. DNS servers</b><span class=m>below: up to 5, the next one is used only when the previous one fails</span></div></div>
<h2>PRESETS</h2>
<div class=row><button onclick="preset('1.1.1.3:300,1.0.0.3:250,208.67.222.123:250,94.140.14.15:700')">Recommended chain</button>
<button onclick="preset('1.1.1.3:300,1.0.0.3:250,208.67.222.123:250,208.67.220.123:250,94.140.14.15:700')">Max safety (5 servers)</button>
<button onclick="preset('1.1.1.3:250,1.0.0.3:250')">Cloudflare only</button><button onclick="preset('208.67.222.123:250,208.67.220.123:250')">Cisco FamilyShield</button>
<button onclick="preset('94.140.14.15:900,94.140.15.16:900')">AdGuard only</button>
<button onclick="preset('1.1.1.1:250,1.0.0.1:250')" title="Only the ESP32's own blocklist blocks; other names go to plain Cloudflare">Local list only</button>
<button onclick="preset('9.9.9.9:400')">Quad9 (no adult filter)</button></div>
<div class=m style=margin-bottom:8px><b>Recommended</b>: Cloudflare &rarr; Cloudflare #2 &rarr; Cisco &rarr; AdGuard, timeouts tuned on this network (300 / 250 / 250 / 700 ms). <b>Max safety</b>: five family servers in a row (Cloudflare &rarr; Cisco &rarr; AdGuard). <b>Cisco FamilyShield</b>: Cisco OpenDNS, blocks adult sites, no SafeSearch.
<b>Local list only</b>: blocking comes only from this device's own list; other names go to plain, fast Cloudflare (no adult filter, no SafeSearch).</div>
<h2>SERVERS</h2><div class=box>
<div class=row>Mode <label><input type=radio name=um id=umc checked onchange="upDirty=true;upMode()"> Chain (failover)</label><label><input type=radio name=um id=ums onchange="upDirty=true;upMode()"> Single</label></div>
<div id=urows></div><div class=row><button class=p onclick=saveUps()>Save</button><button onclick="upDirty=false;upSaved='';load()">Undo changes</button><span id=uinfo class=m></span></div>
<div class=m>Lookups go to server 1. The next server is used only when the previous one fails (timeout, SERVFAIL, REFUSED or a bad reply). Timeouts 50&ndash;1500 ms.</div></div>
<h2>LIVE STATS <span class=m>(local filters: since restart &middot; servers: since the last save or restart)</span></h2>
<div class=tw><table id=upt><thead><tr><th>#</th><th>Filter / server</th><th>Answers</th><th class=r>Failures</th><th class=r>Avg ms</th><th class=r>Max ms</th><th class=r>Timeout</th></tr></thead><tbody></tbody></table></div>
<div class=m>Answered locally: <b id=lo>0</b> &middot; Failovers: <b id=fo>0</b> &middot; SERVFAIL (every server failed): <b id=sf>0</b></div>
<h2>RECENT FAILURES <span class=m>(last 10 since restart; each one moved the lookup to the next server, or to SERVFAIL after the last)</span></h2>
<div class=tw><table id=ft><thead><tr><th>When</th><th>Server</th><th>Reason</th><th>Name</th></tr></thead><tbody></tbody></table></div>
</section>

<section id=lists>
<h2>TEST A DOMAIN</h2><div class=box>
<div class=row><input id=tdom placeholder="example.com" size=30 onkeydown="if(event.key=='Enter')testDom()"><button class=p onclick=testDom()>Test</button></div><div id=tres class=m>Shows whether a name is blocked, and why.</div></div>
<h2>LOADED BLOCKLIST</h2><div class=box><div id=meta>&hellip;</div><div class=m id=store></div></div>
<h2>UPLOAD A NEW BLOCKLIST</h2><div class=box><form id=upf>
<div class=row><span style=min-width:150px>blocklist.bin</span><input type=file id=blf accept=.bin></div>
<div class=row><span style=min-width:150px>blocklist.json (optional)</span><input type=file id=blj accept=.json></div>
<div class=row><button class=p>Upload</button><span id=upmsg class=m></span></div></form>
<div class=m>Build both files on the PC with <code>tools/update.py</code>. The old list is replaced; settings, custom blocks and exceptions are kept. All DNS lookups stop for the ~10&ndash;15 s the upload takes. The old list is removed first, so if an upload fails, upload a list again.</div></div>
<h2>CUSTOM BLOCKED DOMAINS</h2>
<div class=row><input id=dom placeholder="ads.example.com" size=30><button onclick="listOp('/addblock',dom)">Block</button></div>
<div class=tw><table id=cl><tbody></tbody></table></div>
<h2>ALLOWED EXCEPTIONS</h2>
<div class=row><input id=adom placeholder="app.link" size=30><button onclick="listOp('/addallow',adom)">Allow</button></div>
<div class=m style=margin-bottom:6px>An allowed name (and its subdomains) is never blocked by the list or a custom rule. The upstream filter still applies.</div>
<div class=tw><table id=al><tbody></tbody></table></div>
</section>

<section id=devices>
<div class=tw><table id=ct><thead><tr><th>Client</th><th>MAC</th><th>Blocked</th><th>Allowed</th><th></th></tr></thead><tbody></tbody></table></div>
<div class=m>When the router forwards DNS to this device, most lookups show up under one client: the router. It has no Ban button: banning it would block every device.</div>
</section>

<section id=system>
<h2>FIRMWARE UPDATE</h2>
<div class=box id=fwota><form id=fwf><div class=row><input type=file id=fwb accept=.bin><button class=p>Install firmware</button><span id=fwmsg class=m></span></div></form>
<div class=m>Pick <code>firmware.bin</code> from <code>.pio/build/esp32dev/</code> (or <code>tools/out/</code>). It is written to the spare slot and checked first, so a damaged upload is refused. If the new firmware crashes or restarts before it has answered a lookup, the device goes back to the previous one by itself. Max size <span id=fwmax></span>.</div></div>
<div class=box id=fwusb style=display:none>This partition layout has a single app slot, so firmware is flashed over USB: hold <b>IO0</b>, run esptool (see <code>SETUP.md</code>), and release IO0 as soon as writing starts.</div>
<h2>DEVICE</h2><div class=box id=dev></div>
<h2>WIFI</h2><div class=box><button onclick="if(confirm('Forget saved WiFi and reboot into the setup portal?'))forgetWifi()">Forget WiFi</button>
<span class=m>Clears the network picked in the setup portal and restarts. If Wi-Fi details are also built into the firmware (secrets.h), it rejoins that network; if it can't join any, it opens the open setup Wi-Fi C3-AdBlock-XXXX.</span></div>
</section>
</div><script>
function fmt(n){return(n||0).toLocaleString('en-US')}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function mb(b){return(b/1048576).toFixed(2)+' MB'}
const $=id=>document.getElementById(id);let S={},META=null;
// A plain <img>/<form> CSRF can't set a custom header, only same-origin fetch()
// can — so requiring this on every mutating request blocks drive-by CSRF even
// though the server can't otherwise tell a forged request from a real one over
// plain HTTP Basic Auth (browsers auto-replay cached Basic Auth cross-origin).
const CSRF_HDRS={'X-Requested-With':'c3-adblock'}
function tab(){let t=(location.hash||'#overview').slice(1);if(!$(t)||$(t).tagName!='SECTION')t='overview';
document.querySelectorAll('section').forEach(s=>s.classList.toggle('on',s.id==t));document.querySelectorAll('nav a').forEach(a=>a.classList.toggle('on',a.hash=='#'+t))}
addEventListener('hashchange',tab);tab();
// Upstream picker: known resolvers + custom IP; 1 row in Single mode, up to 5 in Chain mode.
const UPS=[['1.1.1.3','Cloudflare Families'],['1.0.0.3','Cloudflare Families #2'],['94.140.14.15','AdGuard Family'],['94.140.15.16','AdGuard Family #2'],
['208.67.222.123','Cisco OpenDNS FamilyShield'],['208.67.220.123','Cisco OpenDNS FamilyShield #2'],
['1.1.1.1','Cloudflare (no filter)'],['1.0.0.1','Cloudflare #2 (no filter)'],['208.67.222.222','Cisco OpenDNS Home (no filter)'],['208.67.220.220','Cisco OpenDNS Home #2 (no filter)'],['9.9.9.9','Quad9 (no adult filter)']];
const UFILT=['1.1.1.3','1.0.0.3','94.140.14.15','94.140.15.16','208.67.222.123','208.67.220.123'];
const R5=[0,1,2,3,4];
urows.innerHTML=R5.map(i=>`<div id=ur${i} class=row>${i+1}. <select id=us${i} onchange=upEdit()>${i?'<option value="">— none —</option>':''}${UPS.map(u=>`<option value=${u[0]}>${u[1]} (${u[0]})</option>`).join('')}<option value=c>Custom IP…</option></select>
<input id=uc${i} placeholder="IP address" size=14 style=display:none oninput=upEdit()> timeout <input id=uto${i} size=4 oninput=upEdit()> ms</div>`).join('');
function setRows(a){(a.length==1?ums:umc).checked=true;
R5.forEach(i=>{let u=a[i];if(!u){$('us'+i).value=i?'':'1.1.1.3';$('uto'+i).value=i==4?700:250;return}
let known=UPS.some(k=>k[0]==u[0]);$('us'+i).value=known?u[0]:'c';$('uc'+i).value=known?'':u[0];$('uto'+i).value=u[1]});upMode()}
// The form follows the device's saved servers (also when they change from another tab) until you edit it.
let upSaved='',upDirty=false;
function upFill(s){let sp=s.ups.map(u=>u.ip+':'+u.to).join(',');if(sp!=upSaved&&!upDirty){upSaved=sp;setRows(s.ups.map(u=>[u.ip,u.to]))}}
function upEdit(){upDirty=true;upChg()}
function preset(spec){setRows(spec.split(',').map(x=>x.split(':')));upEdit()}
function upList(){let a=[];for(let i=0;i<(ums.checked?1:5);i++){let v=$('us'+i).value;if(v)a.push([v=='c'?$('uc'+i).value.trim():v,parseInt($('uto'+i).value)||0])}return a}
function upChg(){R5.forEach(i=>$('uc'+i).style.display=$('us'+i).value=='c'?'':'none');
let a=upList(),w=a.reduce((t,u)=>t+u[1],0),uf=a.some(u=>!UFILT.includes(u[0]));
uinfo.innerHTML='worst case '+(w/1000).toFixed(2)+' s'+(w>1500?' &mdash; <span class=b>long: the router may fall back to the ISP DNS</span>':'')+(uf?' &mdash; <span class=b>includes an unfiltered server</span>':'')+(a.length==1?' &mdash; <span class=b>single server: a timeout means SERVFAIL</span>':'')+(upDirty?' &mdash; <b>not saved yet</b>':'')}
function upMode(){[1,2,3,4].forEach(i=>$('ur'+i).style.display=ums.checked?'none':'');upChg()}
function setList(on){fetch('/setlist?on='+(on?1:0),{headers:CSRF_HDRS}).then(load)}
function saveUps(){let a=upList();if(!a.length)return;if(a.some(u=>!u[0])){uinfo.textContent='✗ enter the custom IP address';return}uinfo.textContent='saving...';
fetch('/setupstream?u='+encodeURIComponent(a.map(u=>u[0]+':'+u[1]).join(',')),{headers:CSRF_HDRS}).then(async r=>{let t=await r.text();if(r.ok){upDirty=false;upSaved=''}await load();uinfo.textContent=r.ok?(t=='ok'?'✓ saved':'✓ saved, '+t.replace(/^ok, /,'')):'✗ '+t})}
function togglePause(){fetch(blockstate.dataset.on=='1'?'/pause?s='+pausedur.value:'/resume',{headers:CSRF_HDRS}).then(load);}
// Redraw only on change: rebuilding every 3 s replaced buttons mid-click, so some clicks were lost.
function put(el,h){if(el._h!==h){el._h=h;el.innerHTML=h}}
function rows(list,op){return list.map(d=>`<tr><td>${esc(d)}</td><td style=text-align:right><button data-op=${op} data-d="${esc(d)}">remove</button></td></tr>`).join('')||'<tr><td class=m>none yet</td></tr>'}
let BUILD='';
async function load(){let s=S=await(await fetch('/stats.json')).json();
if(!BUILD){BUILD=s.build||'';fwCheck(s)}else if(s.build&&s.build!=BUILD){location.reload();return}   // firmware changed: get the new page
host.textContent='@ '+s.ip;credwarn.style.display=s.defcreds?'block':'none';
let on=s.blocking!==false;blockstate.dataset.on=on?'1':'0';blockdot.textContent=on?'🛡️':'⏸️';
blockstate.textContent=on?'Blocking active':(s.resumeIn>0?'Paused — resumes in '+s.resumeIn+'s':'Paused');
pausebtn.textContent=on?'Pause':'Resume';pausedur.style.display=on?'':'none';
put(sys,[['Total blocked',fmt(s.blocked),'b'],['Total allowed',fmt(s.allowed),'a'],['Blocklist domains'+(s.listOn===false?' (OFF)':''),fmt(s.domains),s.listOn===false?'b':''],['Clients',s.clients.length,''],
['WiFi',s.rssi+' dBm',''],['Temp',s.temp+' °C',''],['Free RAM',Math.round(s.heap/1024)+' KB',''],['Uptime',s.uptime,''],
['Failovers / SERVFAIL',fmt(s.failovers)+' / '+fmt(s.servfail),s.servfail?'b':''],['Storage',mb(s.fsUsed)+' / '+mb(s.fsTotal),'']]
.map(c=>`<div class=card><div class="v ${c[2]}">${c[1]}</div><div class=l>${c[0]}</div></div>`).join(''));
put(chain,(s.listOn===false?'<span class=b>Local blocklist OFF</span>':'<b>Local blocklist</b> <span class=m>'+fmt(s.domains)+' domains</span>')+' &rarr; '+
s.ups.map(u=>'<b>'+esc(u.name)+'</b> <span class=m>'+u.ip+', '+u.to+' ms</span>'+(u.filtered?'':' <span class=tag style=color:#f85149>UNFILTERED</span>')).join(' &rarr; ')+(s.ups.length==1?' <span class=m>(single server, no failover)</span>':''));
lston.checked=s.listOn!==false;
put(lstinfo,fmt(s.domains)+' domains'+(META?' &middot; '+esc(META.preset||'custom')+', built '+esc(String(META.built||'?').slice(0,10)):'')+(s.listOn===false?' &mdash; <span class=b>OFF: names on this list are not blocked</span>':' &mdash; <span class=a>ON</span>'));
put(cusinfo,s.custom.length+' blocked, '+(s.allow||[]).length+' allowed <span class=m>(edit on the Lists tab)</span>');
upFill(s);let uf=s.ups.filter(u=>!u.filtered),wm=[];
if(uf.length)wm.push('⚠️ <b>Adult filtering is OFF</b> for lookups answered by '+uf.map(u=>esc(u.name+' '+u.ip)).join(', ')+' &mdash; only the local blocklist protects those lookups.');
if(s.listOn===false)wm.push('⚠️ <b>Local blocklist is OFF</b> &mdash; only your custom blocks and the DNS servers filter lookups (turn it on in DNS &rarr; Filters).');
else if(!s.domains)wm.push('⚠️ <b>NO BLOCKLIST LOADED</b> &mdash; the local list blocks nothing until you upload one (Lists tab).');
uwarn.style.display=wm.length?'block':'none';put(uwarn,wm.join('<br>'));
// Local filters first (numbered like the FILTERS box), then the servers as 3.1, 3.2, ... Every cell has a value:
// red only for real blocks/failures, "—" only where nothing was measured yet. Local filters never wait on the network.
const L=s.local||{},lms=us=>((us||0)/1000).toFixed(2),pct=n=>L.checked?' ('+(100*n/L.checked).toFixed(1)+'%)':'',off=s.listOn===false,LOC='<span class=m>none (local)</span>';
const row=(no,name,ans,cls,fail,avg,max,to)=>`<tr><td>${no}</td><td>${name}</td><td class="${cls}">${ans}</td><td class="r${fail>0?' b':''}">${fmt(fail)}</td><td class=r>${avg}</td><td class=r>${max}</td><td class=r>${to}</td></tr>`;
put(upt.tBodies[0],
row(1,`<b>Local blocklist</b> <span class=m>${fmt(s.domains)} domains</span> ${off?'<span class=tag style=color:#f85149>OFF</span>':'<span class=tag style=color:#3fb950>ON</span>'}<br><span class=m>checked ${fmt(L.checked)} lookups</span>`,
 off?'off':fmt(L.list)+' blocked'+pct(L.list),L.list&&!off?'b':'',0,off?'&mdash;':lms(L.listUs),off?'&mdash;':lms(L.listMax),LOC)+
row(2,`Custom blocks <span class=m>${s.custom.length} domains</span>`,fmt(L.custom)+' blocked'+pct(L.custom),L.custom?'b':'',0,lms(L.customUs),lms(L.customMax),LOC)+
row(2,`Exceptions <span class=m>${(s.allow||[]).length} domains</span>`,fmt(L.allow)+' let through'+pct(L.allow),L.allow?'a':'',0,lms(L.allowUs),lms(L.allowMax),LOC)+
(L.ban?row('&ndash;','Banned devices',fmt(L.ban)+' blocked','b',0,'&mdash;','&mdash;',LOC):'')+
s.ups.map((u,i)=>row('3.'+(i+1),esc(u.name)+' <span class=m>'+u.ip+'</span>'+(u.filtered?'':' <span class=tag style=color:#f85149>UNFILTERED</span>'),
 fmt(u.ok)+' answered',u.ok?'a':'',u.fail,u.ok?u.avg:'&mdash;',u.ok?u.max:'&mdash;',u.to+' ms')).join(''));
const loc=(L.list||0)+(L.custom||0)+(L.ban||0),all=(L.checked||0)+(L.ban||0);
lo.textContent=fmt(loc)+' of '+fmt(all)+(all?' ('+(100*loc/all).toFixed(1)+'%)':'');fo.textContent=fmt(s.failovers);sf.textContent=fmt(s.servfail);
put(ft.tBodies[0],(s.fails||[]).map(f=>'<tr><td>'+(f.ago<120?f.ago+' s':Math.round(f.ago/60)+' min')+' ago</td><td>'+esc(f.up)+'</td><td class=b>'+esc(f.why)+'</td><td>'+esc(f.name)+'</td></tr>').join('')||'<tr><td colspan=4 class=m>none since restart</td></tr>');
put(ct.tBodies[0],s.clients.sort((a,b)=>(b.blocked+b.allowed)-(a.blocked+a.allowed)).map(c=>
`<tr><td>${c.ip}${c.banned?' <span class=tag style=color:#f85149>BANNED</span>':''}</td><td>${c.mac}</td>
<td class=b>${fmt(c.blocked)}</td><td class=a>${fmt(c.allowed)}</td><td>${c.ip==s.gw&&!c.banned?'<span class=m>router</span>':`<button class=ban data-ip="${c.ip}">${c.banned?'Unban':'Ban'}</button>`}</td></tr>`).join('')+
(s.bans||[]).filter(ip=>!s.clients.some(c=>c.ip==ip)).map(ip=>`<tr><td>${esc(ip)} <span class=tag style=color:#f85149>BANNED</span></td><td class=m>not seen since restart</td><td></td><td></td><td><button class=ban data-ip="${esc(ip)}">Unban</button></td></tr>`).join(''));
put(cl.tBodies[0],rows(s.custom,'/unblock'));put(al.tBodies[0],rows(s.allow||[],'/unallow'));
store.textContent='Storage: '+mb(s.fsUsed)+' of '+mb(s.fsTotal)+' used (list + settings)';
put(listsum,'<b>'+fmt(s.domains)+'</b> domains'+(META?' &middot; '+esc(META.preset||'custom')+' &middot; built '+esc(String(META.built||'?').slice(0,10)):'')+' &middot; storage '+mb(s.fsUsed)+' of '+mb(s.fsTotal));
fwota.style.display=s.ota?'':'none';fwusb.style.display=s.ota?'none':'';fwmax.textContent=mb(s.otaMax||0);
put(dev,'IP <b>'+s.ip+'</b> &middot; firmware built '+esc(s.build||'?')+(s.otaState=='pending'?' <b class=b>(new, not confirmed yet: it is once it answers a lookup)</b>':'')+' &middot; uptime '+s.uptime+' &middot; last start: '+esc(s.reset||'?')+' &middot; free RAM '+Math.round(s.heap/1024)+' KB &middot; '+s.temp+' °C &middot; Wi-Fi '+s.rssi+' dBm<br>Flash layout: '+(s.ota?'two app slots (firmware updates from this page)':'single app slot (USB updates only)')+' &middot; storage '+mb(s.fsUsed)+' of '+mb(s.fsTotal))}
async function loadMeta(){let r=await fetch('/blocklist.json');META=null;
if(!r.ok){meta.innerHTML='No details for this list (it was uploaded without <code>blocklist.json</code>).';return}
try{let m=META=await r.json();meta.innerHTML='<b>'+fmt(+m.domains)+'</b> domains &middot; preset <b>'+esc(m.preset||'custom')+'</b> &middot; built '+esc(String(m.built||'?').replace('T',' ').slice(0,16))+
'<br>'+(m.sources||[]).map(x=>'&bull; '+esc(x.name||x.id)).join('<br>')}catch(_){meta.textContent='blocklist.json is not valid JSON'}}
async function testDom(){let d=tdom.value.trim();if(!d)return;tres.textContent='testing...';
let r=await fetch('/test?d='+encodeURIComponent(d),{headers:CSRF_HDRS});if(!r.ok){tres.textContent='✗ '+await r.text();return}
let t=await r.json(),h={blocklist:'<b class=b>BLOCKED</b> by the local blocklist (matched <code>'+esc(t.match)+'</code>)',
'custom-block':'<b class=b>BLOCKED</b> by your custom block list (<code>'+esc(t.match)+'</code>)',
allowed:'<b class=a>ALLOWED</b> by your exception <code>'+esc(t.match)+'</code>, so it goes to the upstream',upstream:'Not on any list, so it goes to the upstream'}[t.verdict];
if(!t.blocking&&t.verdict!='upstream')h+=' &mdash; but blocking is <b>paused</b>, so it is forwarded';
if(t.upstream){h+='<br>Upstream: <b>'+esc(t.upstream)+'</b>'+(t.filtered===false?' <span class=tag style=color:#f85149>UNFILTERED</span>':'')+(t.rcode?' &middot; '+t.rcode:'')+' &middot; '+t.ms+' ms';
if(t.answers)h+='<br>Answer: <code>'+esc(t.answers)+'</code>'+(/(^|, )0\.0\.0\.0($|,)|94\.140\.14\.35|146\.112\.61\.\d+/.test(t.answers)?' &mdash; <b class=b>blocked by the upstream filter</b>':'')}
if(S.listOn===false)h+='<br><span class=m>The local blocklist is switched off (DNS &rarr; Filters).</span>';
tres.innerHTML=h}
function listOp(url,inp){let d=inp.value.trim();if(d)fetch(url+'?d='+encodeURIComponent(d),{headers:CSRF_HDRS}).then(async r=>{if(r.ok)inp.value='';else alert(await r.text());load()})}
document.addEventListener('click',e=>{let t=e.target;if(t.dataset.op)fetch(t.dataset.op+'?d='+encodeURIComponent(t.dataset.d),{headers:CSRF_HDRS}).then(load);
if(t.classList.contains('ban')&&(t.textContent=='Unban'||confirm('Ban '+t.dataset.ip+'? Every lookup from it will get 0.0.0.0.')))
fetch('/ban?ip='+t.dataset.ip,{headers:CSRF_HDRS}).then(async r=>{if(!r.ok)alert(await r.text());load()})});
function forgetWifi(){fetch('/forgetwifi',{headers:CSRF_HDRS}).then(r=>r.text()).then(t=>alert(t))}
// The device closes an upload that arrives without a valid login (a slow fake upload could stall DNS), so log in first.
async function login(msg){let r=await fetch('/auth',{headers:CSRF_HDRS});if(!r.ok)msg.textContent='✗ '+(r.status==401?'log in first':await r.text());return r.ok}
// After an install the page reloads: say whether the build really changed (a dropped connection also looked like success).
function fwCheck(s){let f=null;try{f=sessionStorage.getItem('fwFrom');sessionStorage.removeItem('fwFrom')}catch(_){}if(f==null)return;location.hash='#system';
fwmsg.innerHTML=s.build!=f?'✓ now running the build from '+esc(s.build):'<b class=b>⚠️ still the build from '+esc(f)+'</b> &mdash; fine if you re-installed the same file, otherwise the update did not take'}
// blocklist.bin = ascending 5-byte little-endian hashes (tools/build_blocklist.py); compare from the top byte down.
async function sorted5(f){let b=new Uint8Array(await f.arrayBuffer());for(let i=5;i<b.length;i+=5)for(let k=4;k>=0;k--)if(b[i+k]!=b[i-5+k]){if(b[i+k]<b[i-5+k])return false;break}return true}
// XHR (not fetch) so big uploads can show progress; same CSRF header + Basic Auth as everything else.
function post(url,file,msg){return new Promise(res=>{let x=new XMLHttpRequest(),fd=new FormData();fd.append('f',file);x.open('POST',url);x.setRequestHeader('X-Requested-With','c3-adblock');
x.upload.onprogress=e=>{if(e.lengthComputable)msg.textContent='uploading '+Math.round(100*e.loaded/e.total)+'%'};
x.onload=()=>res({ok:x.status==200,status:x.status,text:x.responseText});x.onerror=()=>res({ok:false,status:0,text:'connection lost'});x.send(fd)})}
upf.onsubmit=async e=>{e.preventDefault();let f=blf.files[0];if(!f){upmsg.textContent='choose blocklist.bin first';return}
if(f.size%5){upmsg.textContent='✗ not a blocklist.bin (size must be a multiple of 5 bytes)';return}
if(S.fsTotal&&f.size>S.fsTotal-65536){upmsg.textContent='✗ too big for this device: '+mb(f.size)+' (max '+mb(S.fsTotal-65536)+')';return}
// The device removes the old list before the new one arrives, so a wrong file of the right size (10 bytes of text) left it with junk.
if(!await sorted5(f)){upmsg.textContent='✗ not a blocklist.bin (its entries are not in order)';return}
if(f.size/5<1000&&!confirm('This list has only '+fmt(f.size/5)+' domains. Replace the current list ('+fmt(S.domains)+' domains)?'))return;
if(!await login(upmsg))return;
let r=await post('/upload',f,upmsg);if(!r.ok){upmsg.textContent='✗ '+(r.text||'HTTP '+r.status);return}
let j=blj.files[0];if(j){r=await post('/uploadmeta',j,upmsg);upmsg.textContent=r.ok?'✓ list and details updated':'✓ list updated, ✗ details: '+r.text}else upmsg.textContent='✓ list updated (no details file)';
blf.value='';blj.value='';await loadMeta();load()};
fwf.onsubmit=async e=>{e.preventDefault();let f=fwb.files[0];if(!f)return;
if(new Uint8Array(await f.slice(0,1).arrayBuffer())[0]!=0xE9){fwmsg.textContent='✗ not an ESP32 firmware image';return}
if(S.otaMax&&f.size>S.otaMax){fwmsg.textContent='✗ '+mb(f.size)+' is bigger than the slot ('+mb(S.otaMax)+')';return}
if(!confirm('Install '+f.name+' ('+mb(f.size)+') and restart? DNS stops for about 20 seconds.'))return;
if(!await login(fwmsg))return;
try{sessionStorage.setItem('fwFrom',S.build||'')}catch(_){}
let r=await post('/update',f,fwmsg);
if(r.ok||r.status==0){fwmsg.textContent='✓ uploaded, restarting… this page reloads in 20 s and then shows which build is running';setTimeout(()=>location.reload(),20000)}
else{try{sessionStorage.removeItem('fwFrom')}catch(_){}fwmsg.textContent='✗ '+(r.text||'HTTP '+r.status)}};
loadMeta();load();setInterval(load,3000);
</script></body></html>)HTML";
