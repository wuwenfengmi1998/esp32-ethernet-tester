#include "wifi_web.h"
#include "weblog.h"
#include "cert_store.h"
#include "pcap.h"
#include <WiFi.h>
#include <ESPmDNS.h>
#include <ESPAsyncWebServer.h>
#include <LittleFS.h>

// =============================================================================
// Embedded control page
// =============================================================================
static const char INDEX_HTML[] PROGMEM = R"HTML(
<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ESP32 Ethernet Tester</title>
<style>
 body{font-family:system-ui,sans-serif;margin:0;background:#0f1419;color:#e6e6e6}
 header{background:#1f6feb;padding:12px 16px;font-size:18px;font-weight:600}
 .wrap{padding:16px;max-width:760px;margin:auto}
 .card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px;margin:12px 0}
 h2{font-size:14px;margin:0 0 10px;color:#8b949e;text-transform:uppercase;letter-spacing:.05em}
 table{width:100%;border-collapse:collapse;font-size:14px}
 td{padding:3px 6px}td:first-child{color:#8b949e;width:45%}
 button{background:#238636;border:0;color:#fff;padding:8px 12px;border-radius:6px;margin:3px;cursor:pointer;font-size:13px}
 button.warn{background:#9e6a03}button.stop{background:#b62324}
 input,select{background:#0d1117;border:1px solid #30363d;color:#e6e6e6;padding:6px;border-radius:6px;margin:3px 0;width:100%}
 .row{display:flex;gap:8px}.row>*{flex:1}
 pre{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:10px;font-size:12px;white-space:pre-wrap;max-height:340px;overflow:auto}
 .ok{color:#3fb950}.bad{color:#f85149}
</style></head><body>
<header>ESP32 Ethernet Tester</header>
<div class="wrap">
 <div class="card"><h2>Status</h2>
  <div class="row" style="align-items:center;margin-bottom:8px">
   <label style="flex:0 0 auto;color:#8b949e">Auto-refresh
    <select id="ri" style="width:auto;display:inline-block" onchange="setAuto()">
     <option value="0">Off</option>
     <option value="1000">1s</option>
     <option value="2000" selected>2s</option>
     <option value="5000">5s</option>
     <option value="10000">10s</option>
    </select></label>
   <button style="flex:0 0 auto" onclick="refresh()">Refresh now</button>
  </div>
  <table id="st"><tr><td>loading...</td></tr></table></div>

 <div class="card"><h2>General / Traffic</h2>
  <div class="row">
   <button onclick="cmd('stats')">Show stats</button>
   <button class="warn" onclick="cmd('stats clear')">Clear stats</button>
   <button onclick="cmd('loopback on')">Loopback on</button>
   <button class="stop" onclick="cmd('loopback off')">Loopback off</button>
  </div>
  <div class="row">
   <input id="smac" placeholder="source MAC XX:XX:..">
   <button onclick="cmd('mac '+v('smac'))">Set MAC</button>
   <input id="tmac" placeholder="target MAC XX:XX:..">
   <button onclick="cmd('target '+v('tmac'))">Set target</button>
  </div>
  <div class="row">
   <input id="scount" type="number" placeholder="count" value="100">
   <input id="ssize" type="number" placeholder="size (bytes)" value="64">
   <button onclick="cmd('send '+v('scount')+' '+v('ssize'))">Send frames</button>
  </div>
 </div>

 <div class="card"><h2>Error Injection</h2>
  <div class="row">
   <button onclick="cmd('inject runt')">Runt</button>
   <button onclick="cmd('inject giant')">Giant</button>
   <button onclick="cmd('inject jumbo')">Jumbo</button>
   <button onclick="cmd('inject badtype')">Bad type</button>
  </div>
  <div class="row">
   <button onclick="cmd('inject broadcast')">Broadcast</button>
   <button onclick="cmd('inject multicast')">Multicast</button>
   <button onclick="cmd('inject pause')">PAUSE</button>
  </div>
  <div class="row">
   <select id="ptype">
    <option>zeros</option><option>ones</option><option>alt</option>
    <option>incr</option><option>random</option>
   </select>
   <input id="plen" type="number" placeholder="len" value="64">
   <input id="pn" type="number" placeholder="count" value="100">
   <button onclick="cmd('inject pattern '+v('ptype')+' '+v('plen')+' '+v('pn'))">Pattern</button>
  </div>
  <div class="row">
   <input id="srate" type="number" placeholder="storm rate (Hz)" value="1000">
   <button class="warn" onclick="cmd('inject storm '+v('srate'))">Start storm</button>
  </div>
  <div class="row">
   <select id="ctype">
    <option>giant</option><option>jumbo</option><option>badtype</option>
    <option>broadcast</option><option>multicast</option><option>pause</option><option>pattern</option>
   </select>
   <input id="crate" type="number" placeholder="rate (fps)" value="1000">
   <button class="warn" onclick="cmd('inject continuous '+v('ctype')+' '+v('crate'))">Start cont.</button>
  </div>
  <div class="row">
   <button class="stop" onclick="cmd('inject stop')">Stop all (storm + continuous)</button>
  </div>
 </div>

 <div class="card"><h2>RFC 2544 Tests (needs DUT loopback)</h2>
  <div class="row"><input id="rsize" type="number" placeholder="frame size (optional)"></div>
  <div class="row">
   <button onclick="cmd('test throughput '+v('rsize'))">Throughput</button>
   <button onclick="cmd('test latency '+v('rsize'))">Latency</button>
   <button onclick="cmd('test frameloss '+v('rsize'))">Frame loss</button>
  </div>
  <div class="row">
   <button onclick="cmd('test backtoback '+v('rsize'))">Back-to-back</button>
   <button class="warn" onclick="cmd('test all')">Full suite</button>
  </div>
 </div>

 <div class="card"><h2>Neighbour Discovery (LLDP / CDP)</h2>
  <div class="row">
   <input id="dsec" type="number" placeholder="listen seconds" value="65">
   <button onclick="cmd('discover '+v('dsec'))">Listen</button>
  </div>
 </div>

 <div class="card"><h2>Neighbour Advertisement (TX)</h2>
  <div class="row">
   <button onclick="cmd('advertise')">Show config</button>
   <button onclick="cmd('advertise lldp on')">LLDP on</button>
   <button class="stop" onclick="cmd('advertise lldp off')">LLDP off</button>
   <button onclick="cmd('advertise cdp on')">CDP on</button>
   <button class="stop" onclick="cmd('advertise cdp off')">CDP off</button>
  </div>
  <div class="row">
   <input id="aname" placeholder="system name">
   <button onclick="cmd('advertise name '+v('aname'))">Set name</button>
   <input id="aport" placeholder="port ID">
   <button onclick="cmd('advertise port '+v('aport'))">Set port</button>
  </div>
  <div class="row">
   <input id="aplat" placeholder="platform string">
   <button onclick="cmd('advertise platform '+v('aplat'))">Set platform</button>
   <input id="aip" placeholder="mgmt IP a.b.c.d">
   <button onclick="cmd('advertise ip '+v('aip'))">Set IP</button>
  </div>
  <div class="row">
   <input id="avlan" type="number" placeholder="VLAN id">
   <button onclick="cmd('advertise vlan '+v('avlan'))">Set VLAN</button>
   <input id="attl" type="number" placeholder="TTL secs">
   <button onclick="cmd('advertise ttl '+v('attl'))">Set TTL</button>
   <input id="aint" type="number" placeholder="interval secs">
   <button onclick="cmd('advertise interval '+v('aint'))">Set interval</button>
  </div>
  <div class="row">
   <button class="stop" onclick="cmd('advertise off')">Disable LLDP + CDP</button>
  </div>
 </div>

 <div class="card"><h2>L3 / IP (Ethernet side)</h2>
  <div class="row">
   <button onclick="cmd('ip show')">Show IP</button>
   <button onclick="cmd('ip dhcp')">IP via DHCP</button>
  </div>
  <div class="row">
   <input id="sip" placeholder="ip">
   <input id="smask" placeholder="mask">
   <input id="sgw" placeholder="gateway">
   <button onclick="cmd('ip static '+v('sip')+' '+v('smask')+' '+v('sgw'))">Set static</button>
  </div>
 </div>

 <div class="card"><h2>DHCP Server Test</h2>
  <div class="row">
   <button onclick="cmd('dhcp discover')">DORA</button>
   <button onclick="cmd('dhcp detect')">Detect</button>
   <button class="warn" onclick="cmd('dhcp flood 50')">Starvation x50</button>
  </div>
  <div class="row">
   <button class="warn" onclick="cmd('dhcp decline')">Decline</button>
   <button class="warn" onclick="cmd('dhcp nak')">NAK test</button>
   <button class="warn" onclick="cmd('dhcp malformed')">Malformed</button>
   <button class="warn" onclick="cmd('dhcp renew')">Renew</button>
  </div>
 </div>

 <div class="card"><h2>Reachability Probe (mDNS)</h2>
  <div class="row"><input id="host" placeholder="hostname (e.g. printer.local)">
   <button onclick="cmd('probe '+v('host'))">Probe</button></div>
 </div>

 <div class="card"><h2>802.1X / AAA Port Authentication</h2>
  <div class="row">
   <input id="d1xuser" placeholder="identity / username">
   <button onclick="cmd('dot1x user '+v('d1xuser'))">Save user</button>
   <input id="d1xpass" type="password" placeholder="password (MD5 / PEAP)">
   <button onclick="cmd('dot1x pass '+v('d1xpass'))">Save pass</button>
  </div>
  <div class="row">
   <button onclick="cmd('dot1x probe')">Probe port (detect NAC)</button>
   <button onclick="cmd('dot1x auth')">Authenticate</button>
   <button class="stop" onclick="cmd('dot1x logoff')">Logoff</button>
  </div>
 </div>

 <div class="card"><h2>EAP-TLS Certificates (AAA with TLS)</h2>
  <label>EAP method
   <select id="d1xmethod" onchange="cmd('dot1x method '+v('d1xmethod'))">
    <option value="md5">EAP-MD5 (password)</option>
    <option value="peap">PEAPv0/EAP-MSCHAPv2 (password)</option>
    <option value="ttls-pap">EAP-TTLS/PAP (password)</option>
    <option value="ttls-mschap">EAP-TTLS/MSCHAPv2 (password)</option>
    <option value="tls">EAP-TLS (certificate)</option>
   </select></label>
  <table id="certst" style="margin:6px 0"><tr><td>loading...</td></tr></table>
  <div class="row">
   <input type="file" id="caf" accept=".pem,.crt,.cer">
   <button onclick="upCert('ca','caf')">Upload CA</button>
  </div>
  <div class="row">
   <input type="file" id="clf" accept=".pem,.crt,.cer">
   <button onclick="upCert('client','clf')">Upload client cert</button>
  </div>
  <div class="row">
   <input type="file" id="kyf" accept=".pem,.key">
   <button onclick="upCert('key','kyf')">Upload client key</button>
  </div>
  <div class="row">
   <input id="d1xkeypass" type="password" placeholder="key passphrase (optional)">
   <button onclick="cmd('dot1x keypass '+v('d1xkeypass'))">Save passphrase</button>
   <button class="stop" onclick="if(confirm('Remove all certificates?'))cmd('dot1x cert clear all')">Clear all</button>
  </div>
 </div>

 <div class="card"><h2>Reconnaissance</h2>
  <div class="row">
   <input id="rsweepa" placeholder="start IP">
   <input id="rsweepb" placeholder="end IP">
   <button onclick="cmd('recon sweep '+v('rsweepa')+' '+v('rsweepb'))">Ping sweep</button>
  </div>
  <div class="row">
   <input id="arpa" placeholder="start IP">
   <input id="arpb" placeholder="end IP">
   <button onclick="cmd('arp scan '+v('arpa')+' '+v('arpb'))">ARP scan</button>
  </div>
  <div class="row">
   <input id="rtrace" placeholder="target IP">
   <button onclick="cmd('recon trace '+v('rtrace'))">Traceroute</button>
   <input id="rpsecs" type="number" value="30" style="width:5em" title="seconds">
   <button onclick="cmd('recon passive '+v('rpsecs'))">Passive map</button>
  </div>
  <div class="row">
   <button onclick="cmd('link')">Link info</button>
   <button onclick="cmd('link monitor')">Link monitor</button>
   <button onclick="cmd('wifi scan')">Wi-Fi scan (rogue AP)</button>
   <button onclick="cmd('ipv6 listen')">IPv6 NDP listen</button>
  </div>
 </div>

 <div class="card"><h2>Packet Capture (PCAP)</h2>
  <div class="row">
   <input id="pcsecs" type="number" value="10" style="width:6em" title="seconds">
   <input id="pcmax" type="number" placeholder="max frames (0=unlim)" style="width:11em">
   <button onclick="cmd('pcap start '+v('pcsecs')+' '+(v('pcmax')||'0'))">Start capture</button>
  </div>
  <div class="row">
   <button onclick="cmd('pcap status')">Status</button>
   <a href="/capture.pcap"><button type="button">Download .pcap</button></a>
   <button class="stop" onclick="cmd('pcap delete')">Delete</button>
  </div>
 </div>

 <div class="card"><h2>TCP Port Scanner</h2>
  <div class="row">
   <input id="scnip" placeholder="target IP">
   <button onclick="cmd('scan common '+v('scnip'))">Scan common ports</button>
  </div>
  <div class="row">
   <input id="scnp1" type="number" placeholder="first port" style="width:7em">
   <input id="scnp2" type="number" placeholder="last port" style="width:7em">
   <button onclick="cmd('scan ports '+v('scnip')+' '+v('scnp1')+' '+v('scnp2'))">Scan range</button>
  </div>
  <div class="row">
   <input id="scnbp" type="number" placeholder="port" style="width:7em">
   <input id="scnpr" placeholder="optional probe string">
   <button onclick="cmd('scan banner '+v('scnip')+' '+v('scnbp')+' '+v('scnpr'))">Banner grab</button>
  </div>
 </div>

 <div class="card"><h2>Offensive / DoS (authorized lab use only)</h2>
  <div class="row">
   <button class="warn" onclick="if(confirm('Enable disruptive/offensive tests? Authorized networks only.'))cmd('arm on')">Arm (enable)</button>
   <button class="stop" onclick="cmd('disarm')">Disarm</button>
   <button onclick="cmd('arm')">Status</button>
  </div>
  <h3 style="margin:8px 0 4px">Layer 2</h3>
  <div class="row">
   <input id="vlvid" type="number" placeholder="VLAN id" style="width:7em">
   <button class="warn" onclick="cmd('l2 vlan '+v('vlvid'))">VLAN inject</button>
   <input id="vldn" type="number" placeholder="native" style="width:6em">
   <input id="vldt" type="number" placeholder="target" style="width:6em">
   <button class="warn" onclick="cmd('l2 dtag '+v('vldn')+' '+v('vldt'))">Double-tag hop</button>
  </div>
  <div class="row">
   <button class="warn" onclick="cmd('l2 dtp')">DTP trunk spoof</button>
   <button class="warn" onclick="cmd('l2 macflood')">CAM flood</button>
   <button class="warn" onclick="cmd('l2 lldpflood')">LLDP flood</button>
   <button class="warn" onclick="cmd('l2 cdpflood')">CDP flood</button>
  </div>
  <div class="row">
   <button onclick="cmd('l2 stp listen')">STP listen</button>
   <button class="warn" onclick="cmd('l2 stp root')">STP root takeover</button>
   <button class="warn" onclick="cmd('l2 stp tcn')">STP TCN flood</button>
  </div>
  <h3 style="margin:8px 0 4px">ARP</h3>
  <div class="row">
   <input id="agip" placeholder="IP to announce">
   <button class="warn" onclick="cmd('arp gratuitous '+v('agip'))">Gratuitous ARP</button>
  </div>
  <div class="row">
   <input id="aspv" placeholder="victim IP">
   <input id="aspg" placeholder="gateway IP">
   <button class="warn" onclick="cmd('arp spoof '+v('aspv')+' '+v('aspg'))">ARP MITM</button>
   <button class="warn" onclick="cmd('arp storm')">ARP storm</button>
  </div>
  <h3 style="margin:8px 0 4px">DHCP / IPv6 / 802.1X</h3>
  <div class="row">
   <input id="dhrp" placeholder="pool start IP">
   <button class="warn" onclick="cmd('dhcp rogue '+v('dhrp'))">Rogue DHCP server</button>
   <button class="warn" onclick="cmd('ipv6 rogue')">Rogue IPv6 RA</button>
  </div>
  <div class="row">
   <button class="warn" onclick="cmd('dot1x startflood')">EAPOL-Start flood</button>
   <input id="lofmac" placeholder="victim MAC">
   <button class="warn" onclick="cmd('dot1x logoffmac '+v('lofmac'))">Spoof Logoff</button>
   <button onclick="cmd('dot1x mab')">MAB probe</button>
  </div>
 </div>

 <div class="card"><h2>Configuration (saved to NVS, reboot to apply)</h2>
  <label><input id="wen" type="checkbox" style="width:auto"> Wi-Fi enabled on boot</label>
  <label>Management mode
   <select id="wmode" onchange="modeUi()">
    <option value="sta">Infrastructure (join Wi-Fi)</option>
    <option value="ap">Access Point (field / phone pairing)</option>
   </select></label>
  <div id="stacfg">
   <input id="ssid" placeholder="Wi-Fi SSID">
   <input id="pass" type="password" placeholder="Wi-Fi password (leave blank to keep)">
  </div>
  <div id="apcfg">
   <input id="apssid" placeholder="AP SSID (broadcast name)">
   <input id="appass" type="password" placeholder="AP password (>=8 chars, blank = open)">
  </div>
  <input id="hn" placeholder="hostname">
  <button onclick="saveCfg()">Save</button>
 </div>

 <div class="card"><h2>System</h2>
  <div class="row">
   <button class="stop" onclick="reboot()">Reboot device</button>
  </div>
 </div>

 <div class="card"><h2>Output <span id="run"></span></h2><pre id="log">(run a command to see results here)</pre></div>
</div>
<script>
function v(i){return document.getElementById(i).value}
let polling=false;
function setRun(r){document.getElementById('run').innerHTML=r?'<span style="color:#d29922">● running...</span>':'<span class="ok">● done</span>';}
function poll(){fetch('/api/result').then(r=>r.json()).then(s=>{
  let log=document.getElementById('log');
  log.textContent=s.output||'(no output)';
  log.scrollTop=log.scrollHeight;
  setRun(s.running);
  if(s.running){setTimeout(poll,600);}else{polling=false;}
}).catch(e=>{polling=false;});}
function cmd(c){
  fetch('/api/cmd',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'c='+encodeURIComponent(c)})
  .then(r=>{if(r.status==409){return r.text().then(t=>{document.getElementById('run').innerHTML='<span class="bad">'+t+'</span>';});}
    document.getElementById('log').textContent='running: '+c+' ...';
    setRun(true);
    if(!polling){polling=true;setTimeout(poll,300);}});
}
function saveCfg(){let b='ssid='+encodeURIComponent(v('ssid'))+'&pass='+encodeURIComponent(v('pass'))
 +'&host='+encodeURIComponent(v('hn'))+'&wifi='+(document.getElementById('wen').checked?'1':'0')
 +'&apmode='+(v('wmode')=='ap'?'1':'0')
 +'&apssid='+encodeURIComponent(v('apssid'))+'&appass='+encodeURIComponent(v('appass'));
 fetch('/api/config',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:b})
 .then(r=>r.text()).then(t=>{document.getElementById('log').textContent=t});}
function modeUi(){let ap=v('wmode')=='ap';
 document.getElementById('stacfg').style.display=ap?'none':'block';
 document.getElementById('apcfg').style.display=ap?'block':'none';}
function reboot(){if(!confirm('Reboot the device now?'))return;
 document.getElementById('log').textContent='Rebooting... reconnect in a few seconds.';
 cmd('reboot');}
function refresh(){fetch('/api/status').then(r=>r.json()).then(s=>{
 let h='';for(let k in s){let val=s[k];
  if(k=='link')val='<span class="'+(val=='UP'?'ok':'bad')+'">'+val+'</span>';
  h+='<tr><td>'+k+'</td><td>'+val+'</td></tr>'}
 document.getElementById('st').innerHTML=h;}).catch(e=>{});}
let autoTimer=null;
function setAuto(){let ms=parseInt(document.getElementById('ri').value);
 if(autoTimer){clearInterval(autoTimer);autoTimer=null;}
 if(ms>0){autoTimer=setInterval(refresh,ms);}}
function loadCfg(){fetch('/api/config').then(r=>r.json()).then(c=>{
 document.getElementById('ssid').value=c.ssid||'';
 document.getElementById('hn').value=c.host||'';
 document.getElementById('wen').checked=!!c.wifi;
 document.getElementById('wmode').value=c.apmode?'ap':'sta';
 document.getElementById('apssid').value=c.apssid||'';
 if(c.hasPass)document.getElementById('pass').placeholder='(password set \u2014 leave blank to keep)';
 if(c.apHasPass)document.getElementById('appass').placeholder='(AP password set \u2014 leave blank to keep)';
 modeUi();
}).catch(e=>{});}
function refreshCerts(){fetch('/api/cert').then(r=>r.json()).then(c=>{
 document.getElementById('d1xmethod').value=c.method||'md5';
 let row=(n,o)=>'<tr><td>'+n+'</td><td>'+(o.present?'<span class="ok">'+o.bytes+' bytes</span>':'<span class="bad">none</span>')+'</td></tr>';
 document.getElementById('certst').innerHTML=row('CA certificate',c.ca)+row('Client certificate',c.client)+row('Client key',c.key)+
  '<tr><td>Key passphrase</td><td>'+(c.keypass?'set':'none')+'</td></tr>';
}).catch(e=>{});}
function upCert(kind,inp){let f=document.getElementById(inp).files[0];
 if(!f){alert('Choose a PEM file first.');return;}
 let fd=new FormData();fd.append('f',f,f.name);
 document.getElementById('log').textContent='Uploading '+kind+' ('+f.name+')...';
 fetch('/api/cert/'+kind,{method:'POST',body:fd})
  .then(r=>r.text()).then(t=>{document.getElementById('log').textContent=t;refreshCerts();})
  .catch(e=>{document.getElementById('log').textContent='Upload failed: '+e;});}
setAuto();refresh();loadCfg();refreshCerts();
</script></body></html>
)HTML";

// =============================================================================
// Command queue (async callback -> main loop)
// =============================================================================
static portMUX_TYPE   s_mux = portMUX_INITIALIZER_UNLOCKED;
static String         s_pending;
static volatile bool  s_havePending = false;
static volatile bool  s_running     = false;
static char           s_curCmd[96]  = {0};

// Escape a string for embedding in a JSON value.
static String jsonEscape(const String &in)
{
    String o;
    o.reserve(in.length() + 16);
    for (size_t i = 0; i < in.length(); i++) {
        char c = in[i];
        switch (c) {
            case '\"': o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            default:
                if ((uint8_t)c < 0x20) { char b[8]; sprintf(b, "\\u%04x", c); o += b; }
                else                   o += c;
        }
    }
    return o;
}

WebControl::WebControl()
{
    strncpy(_hostname, "esp32-tester", sizeof(_hostname) - 1);
    _hostname[sizeof(_hostname) - 1] = '\0';
}

// =============================================================================
// Certificate upload helper (chunked multipart -> LittleFS via cert_store)
// =============================================================================
static bool s_uploadOk = false;

static void certUpload(CertKind kind, size_t index,
                       const uint8_t *data, size_t len, bool final)
{
    if (index == 0) s_uploadOk = certStoreBeginWrite(kind);
    if (s_uploadOk && len && !certStoreWriteChunk(data, len)) s_uploadOk = false;
    if (final) { if (s_uploadOk) certStoreEndWrite(); else certStoreAbortWrite(); }
}

// =============================================================================
// begin — connect Wi-Fi (or AP) and start the server
// =============================================================================
void WebControl::begin(const NetConfig &cfg)
{
    strncpy(_hostname, cfg.hostname[0] ? cfg.hostname : "esp32-tester",
            sizeof(_hostname) - 1);
    _hostname[sizeof(_hostname) - 1] = '\0';

    // Cache config so the web UI can display current NVS settings.
    strncpy(_cfgSsid, cfg.wifiSsid, sizeof(_cfgSsid) - 1);
    _cfgSsid[sizeof(_cfgSsid) - 1] = '\0';
    strncpy(_cfgHost, _hostname, sizeof(_cfgHost) - 1);
    _cfgHost[sizeof(_cfgHost) - 1] = '\0';
    _cfgWifiEn  = cfg.wifiEnabled;
    _cfgHasPass = cfg.wifiPass[0] != '\0';
    _cfgApMode  = cfg.apMode;
    strncpy(_cfgApSsid, cfg.apSsid[0] ? cfg.apSsid : _hostname, sizeof(_cfgApSsid) - 1);
    _cfgApSsid[sizeof(_cfgApSsid) - 1] = '\0';
    _cfgApHasPass = cfg.apPass[0] != '\0';
    _cfgLive      = &cfg;       // live handle for the cert/method status endpoint

    _staConnected = false;
    _apMode       = false;

    // Resolve the soft-AP SSID (fall back to the hostname when unset).
    char apSsid[33];
    strncpy(apSsid, cfg.apSsid[0] ? cfg.apSsid : _hostname, sizeof(apSsid) - 1);
    apSsid[sizeof(apSsid) - 1] = '\0';
    // WPA2-PSK requires >= 8 characters; anything shorter is treated as open.
    const char *apPass = (strlen(cfg.apPass) >= 8) ? cfg.apPass : nullptr;

    if (cfg.wifiEnabled && cfg.apMode) {
        // Deliberate access-point mode for field use (pair a phone/tablet).
        WiFi.mode(WIFI_AP);
        WiFi.softAP(apSsid, apPass);
        _apMode = true;
        _ip = WiFi.softAPIP();
        Serial.printf("WiFi: hosting AP '%s' (%s), IP %s\r\n",
                      apSsid, apPass ? "WPA2" : "open", _ip.toString().c_str());
    } else if (cfg.wifiEnabled && cfg.wifiSsid[0]) {
        WiFi.mode(WIFI_STA);
        WiFi.setHostname(_hostname);
        WiFi.begin(cfg.wifiSsid, cfg.wifiPass);
        Serial.printf("WiFi: connecting to '%s'", cfg.wifiSsid);
        uint32_t deadline = millis() + 12000;
        while (WiFi.status() != WL_CONNECTED && (int32_t)(deadline - millis()) > 0) {
            delay(250); Serial.print('.');
        }
        Serial.println();
        if (WiFi.status() == WL_CONNECTED) {
            _staConnected = true;
            _ip = WiFi.localIP();
            Serial.printf("WiFi: connected, IP %s\r\n", _ip.toString().c_str());
        }
    }

    if (!_staConnected && !_apMode) {
        // Fallback setup AP so the device is always reachable to fix config.
        WiFi.mode(WIFI_AP);
        WiFi.softAP("ESP32-Tester-Setup");
        _apMode = true;
        _ip = WiFi.softAPIP();
        Serial.printf("WiFi: started setup AP 'ESP32-Tester-Setup', IP %s\r\n",
                      _ip.toString().c_str());
    }

    if (MDNS.begin(_hostname)) {
        MDNS.addService("http", "tcp", 80);
        Serial.printf("mDNS: responder up at http://%s.local/\r\n", _hostname);
    }

    AsyncWebServer *srv = new AsyncWebServer(80);
    _server = srv;
    _routes();
    srv->begin();
    Serial.println("Web: control server started on port 80.");
}

// =============================================================================
// Routes
// =============================================================================
void WebControl::_routes()
{
    AsyncWebServer *srv = static_cast<AsyncWebServer *>(_server);

    srv->on("/", HTTP_GET, [](AsyncWebServerRequest *req) {
        req->send_P(200, "text/html", INDEX_HTML);
    });

    srv->on("/api/status", HTTP_GET, [this](AsyncWebServerRequest *req) {
        String json = _statusFn ? _statusFn() : String("{}");
        req->send(200, "application/json", json);
    });

    srv->on("/api/cmd", HTTP_POST, [this](AsyncWebServerRequest *req) {
        if (!req->hasParam("c", true)) { req->send(400, "text/plain", "missing c"); return; }
        String c = req->getParam("c", true)->value();
        bool busy;
        portENTER_CRITICAL(&s_mux);
        busy = s_running || s_havePending;
        if (!busy) { s_pending = c; s_havePending = true; }
        portEXIT_CRITICAL(&s_mux);
        if (busy) {
            req->send(409, "text/plain", "A command is already running. Wait for it to finish.");
        } else {
            req->send(200, "text/plain", "queued");
        }
    });

    srv->on("/api/result", HTTP_GET, [this](AsyncWebServerRequest *req) {
        String out; Out.snapshot(out);
        bool   running = s_running;
        char   cmd[96];
        portENTER_CRITICAL(&s_mux);
        memcpy(cmd, s_curCmd, sizeof(cmd));
        portEXIT_CRITICAL(&s_mux);
        cmd[sizeof(cmd) - 1] = '\0';

        String json = "{\"running\":";
        json += running ? "true" : "false";
        json += ",\"cmd\":\"";   json += jsonEscape(String(cmd));
        json += "\",\"output\":\""; json += jsonEscape(out);
        json += "\"}";
        req->send(200, "application/json", json);
    });

    srv->on("/api/config", HTTP_GET, [this](AsyncWebServerRequest *req) {
        String json = "{\"ssid\":\"";  json += jsonEscape(String(_cfgSsid));
        json += "\",\"host\":\"";       json += jsonEscape(String(_cfgHost));
        json += "\",\"wifi\":";         json += _cfgWifiEn ? "true" : "false";
        json += ",\"hasPass\":";        json += _cfgHasPass ? "true" : "false";
        json += ",\"apmode\":";         json += _cfgApMode ? "true" : "false";
        json += ",\"apssid\":\"";       json += jsonEscape(String(_cfgApSsid));
        json += "\",\"apHasPass\":";    json += _cfgApHasPass ? "true" : "false";
        json += "}";
        req->send(200, "application/json", json);
    });

    srv->on("/api/config", HTTP_POST, [this](AsyncWebServerRequest *req) {
        auto get = [&](const char *k) -> String {
            return req->hasParam(k, true) ? req->getParam(k, true)->value() : String();
        };
        String ssid = get("ssid"), pass = get("pass"), host = get("host");
        bool wifiEn = get("wifi") == "1";
        bool apMode = get("apmode") == "1";
        String apSsid = get("apssid"), apPass = get("appass");
        if (_cfgFn) _cfgFn(ssid, pass, host, wifiEn, apMode, apSsid, apPass);
        // Refresh cached config so the UI reflects the new values immediately.
        strncpy(_cfgSsid, ssid.c_str(), sizeof(_cfgSsid) - 1);
        _cfgSsid[sizeof(_cfgSsid) - 1] = '\0';
        strncpy(_cfgHost, host.c_str(), sizeof(_cfgHost) - 1);
        _cfgHost[sizeof(_cfgHost) - 1] = '\0';
        _cfgWifiEn = wifiEn;
        _cfgApMode = apMode;
        if (apSsid.length()) {
            strncpy(_cfgApSsid, apSsid.c_str(), sizeof(_cfgApSsid) - 1);
            _cfgApSsid[sizeof(_cfgApSsid) - 1] = '\0';
        }
        if (pass.length())   _cfgHasPass   = true;
        if (apPass.length()) _cfgApHasPass = true;
        req->send(200, "text/plain", "Configuration saved. Reboot to apply.");
    });

    // ---- EAP-TLS certificate status + uploads ----
    srv->on("/api/cert", HTTP_GET, [this](AsyncWebServerRequest *req) {
        auto kj = [](CertKind k) {
            String s = "{\"present\":";
            s += certStoreExists(k) ? "true" : "false";
            s += ",\"bytes\":";
            s += String((unsigned)certStoreSize(k));
            s += "}";
            return s;
        };
        String json = "{\"method\":\"";
        json += (_cfgLive && _cfgLive->dot1xMethod == 1) ? "tls"
              : (_cfgLive && _cfgLive->dot1xMethod == 2) ? "peap"
              : (_cfgLive && _cfgLive->dot1xMethod == 3) ? "ttls-pap"
              : (_cfgLive && _cfgLive->dot1xMethod == 4) ? "ttls-mschap" : "md5";
        json += "\",\"keypass\":";
        json += (_cfgLive && _cfgLive->dot1xKeyPass[0]) ? "true" : "false";
        json += ",\"ca\":";     json += kj(CertKind::CA);
        json += ",\"client\":"; json += kj(CertKind::CLIENT);
        json += ",\"key\":";    json += kj(CertKind::KEY);
        json += "}";
        req->send(200, "application/json", json);
    });

    srv->on("/api/cert/ca", HTTP_POST,
        [](AsyncWebServerRequest *req) {
            req->send(200, "text/plain",
                      certStoreExists(CertKind::CA) ? "CA certificate uploaded."
                                                    : "CA upload failed (invalid file?).");
        },
        [](AsyncWebServerRequest *req, const String &fn, size_t index,
           uint8_t *data, size_t len, bool final) {
            certUpload(CertKind::CA, index, data, len, final);
        });

    srv->on("/api/cert/client", HTTP_POST,
        [](AsyncWebServerRequest *req) {
            req->send(200, "text/plain",
                      certStoreExists(CertKind::CLIENT) ? "Client certificate uploaded."
                                                        : "Client cert upload failed.");
        },
        [](AsyncWebServerRequest *req, const String &fn, size_t index,
           uint8_t *data, size_t len, bool final) {
            certUpload(CertKind::CLIENT, index, data, len, final);
        });

    srv->on("/api/cert/key", HTTP_POST,
        [](AsyncWebServerRequest *req) {
            req->send(200, "text/plain",
                      certStoreExists(CertKind::KEY) ? "Client key uploaded."
                                                     : "Client key upload failed.");
        },
        [](AsyncWebServerRequest *req, const String &fn, size_t index,
           uint8_t *data, size_t len, bool final) {
            certUpload(CertKind::KEY, index, data, len, final);
        });

    // ---- PCAP capture download ----
    srv->on("/capture.pcap", HTTP_GET, [](AsyncWebServerRequest *req) {
        fs::FS *fs = pcapFs();
        if (!fs) {
            req->send(404, "text/plain", "No capture stored. Run 'pcap start' first.");
            return;
        }
        AsyncWebServerResponse *res =
            req->beginResponse(*fs, pcapPath(), "application/vnd.tcpdump.pcap");
        res->addHeader("Content-Disposition", "attachment; filename=capture.pcap");
        req->send(res);
    });

    srv->onNotFound([](AsyncWebServerRequest *req) {
        req->send(404, "text/plain", "Not found");
    });
}

// =============================================================================
// loop — execute one queued command per call (output captured for the web UI)
// =============================================================================
void WebControl::loop()
{
    String c;
    bool have = false;
    portENTER_CRITICAL(&s_mux);
    if (s_havePending && !s_running) {
        c = s_pending; s_havePending = false; have = true;
        s_running = true;
        strncpy(s_curCmd, c.c_str(), sizeof(s_curCmd) - 1);
        s_curCmd[sizeof(s_curCmd) - 1] = '\0';
    }
    portEXIT_CRITICAL(&s_mux);

    if (have && _cmdFn) {
        Out.beginCapture();
        Out.printf("[web] %s\r\n", c.c_str());
        _cmdFn(c);          // blocks here; async server keeps serving /api/result
        Out.endCapture();
        s_running = false;
    }
}
