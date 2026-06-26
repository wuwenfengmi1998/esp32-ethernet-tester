#include "wifi_web.h"
#include "weblog.h"
#include "cert_store.h"
#include "pcap.h"
#include "https_srv.h"
#include "ota.h"
#include <WiFi.h>
#include <ESPmDNS.h>
#include <Preferences.h>
#include <ESPAsyncWebServer.h>
#include <LittleFS.h>
#include <Update.h>
#include <esp_task_wdt.h>
#include <esp_timer.h>

// =============================================================================
// Embedded control page
// =============================================================================
static const char INDEX_HTML[] PROGMEM = R"HTML(
<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ethernet Tester</title>
<style>
:root{--bg:#0f1419;--card:#161b22;--border:#30363d;--text:#e6e6e6;--dim:#8b949e;
 --green:#238636;--warn:#9e6a03;--stop:#b62324;--accent:#1f6feb;--input:#0d1117;
 --ok:#3fb950;--bad:#f85149;--tab:#21262d;--tab-active:var(--accent)}
*{box-sizing:border-box}
body{font-family:system-ui,sans-serif;margin:0;background:var(--bg);color:var(--text);font-size:14px}
header{background:var(--accent);padding:6px 16px;position:sticky;top:0;z-index:100}
.hdr-top{display:flex;align-items:center;justify-content:space-between}
header h1{margin:0;font-size:15px;font-weight:600}
.hdr-btns{display:flex;gap:6px;align-items:center}
.hdr-btns button{font-size:12px;padding:5px 10px}
.hdr-btns select{font-size:12px;padding:3px 6px;background:rgba(255,255,255,.15);border:1px solid rgba(255,255,255,.3);color:#fff;border-radius:4px}
#layoutToggle{font-size:11px;padding:4px 8px;background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.3);color:#fff;border-radius:4px;cursor:pointer}
.hdr-stats{display:flex;gap:8px;flex-wrap:wrap;font-size:11px;padding:4px 0 0;opacity:.9}
.hdr-stats span{background:rgba(0,0,0,.25);border-radius:10px;padding:2px 8px;white-space:nowrap}
.desktop .main{display:grid;grid-template-columns:1fr 1fr;gap:0;height:calc(100vh - 68px);overflow:hidden}
.desktop .panel-left{overflow-y:auto;padding:12px;border-right:1px solid var(--border)}
.desktop .panel-right{overflow-y:auto;padding:0}
.mobile .main{display:flex;flex-direction:column;min-height:calc(100vh - 68px)}
.mobile .panel-left{order:1;padding:8px;max-height:200px;overflow-y:auto;border-bottom:1px solid var(--border);flex-shrink:0}
.mobile .panel-right{order:2;overflow-y:auto;flex:1}
.mobile .panel-left.collapsed{max-height:36px;overflow:hidden}
.tabs{display:flex;flex-wrap:wrap;background:var(--tab);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:10}
.tab-btn{background:none;border:none;color:var(--dim);padding:8px 12px;font-size:12px;cursor:pointer;border-bottom:2px solid transparent;white-space:nowrap;margin:0}
.tab-btn.active{color:var(--text);border-bottom-color:var(--tab-active);background:rgba(31,111,235,.1)}
.tab-btn:hover{color:var(--text);background:rgba(255,255,255,.05)}
.tab-content{display:none;padding:12px}
.tab-content.active{display:block}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:12px;margin:0 0 10px}
h2{font-size:13px;margin:0 0 8px;color:var(--dim);text-transform:uppercase;letter-spacing:.05em}
h3{font-size:12px;margin:6px 0 4px;color:var(--dim)}
table{width:100%;border-collapse:collapse;font-size:13px}
td{padding:2px 6px}td:first-child{color:var(--dim);width:45%}
button{background:var(--green);border:0;color:#fff;padding:7px 11px;border-radius:6px;margin:2px;cursor:pointer;font-size:12px;white-space:nowrap}
button.warn{background:var(--warn)}button.stop{background:var(--stop)}
button:active{opacity:.7}
input,select,textarea{background:var(--input);border:1px solid var(--border);color:var(--text);padding:6px 8px;border-radius:6px;margin:2px 0;width:100%;font-size:13px}
textarea{font-family:monospace;resize:vertical;min-height:80px}
.row{display:flex;gap:6px;flex-wrap:wrap;margin:3px 0}.row>*{flex:1;min-width:0}
.row>button{flex:0 0 auto}
pre{background:var(--input);border:1px solid var(--border);border-radius:6px;padding:10px;font-size:12px;
 white-space:pre-wrap;word-break:break-all;overflow-y:auto;margin:0;flex:1;min-height:100px}
.desktop pre{height:calc(100vh - 180px)}
.mobile pre{max-height:140px}
.ok{color:var(--ok)}.bad{color:var(--bad)}
.toggle-out{background:none;border:1px solid var(--border);color:var(--dim);padding:4px 8px;font-size:11px;margin-bottom:6px}
.modal-overlay{display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.6);z-index:200;align-items:center;justify-content:center;padding:16px}
.modal-overlay.show{display:flex}
.modal{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:16px;max-width:500px;width:100%;max-height:80vh;overflow-y:auto}
.modal h2{margin-top:12px}
.modal-close{float:right;background:var(--input);border:1px solid var(--border);color:var(--dim);padding:4px 10px;font-size:14px;cursor:pointer;border-radius:6px}
.file-list{max-height:300px;overflow-y:auto;font-size:12px;font-family:monospace}
.file-list div{padding:3px 6px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center}
.file-list div:hover{background:rgba(255,255,255,.03)}
.file-list .fname{flex:1;overflow:hidden;text-overflow:ellipsis}
.file-list .fsize{color:var(--dim);margin-left:8px;white-space:nowrap}
.file-list .factions button{padding:3px 6px;font-size:11px;margin:0 2px}
@media(max-width:900px){
 body:not(.force-desktop) .main{display:flex!important;flex-direction:column}
 body:not(.force-desktop) .panel-left{order:1;max-height:200px;border-right:none;border-bottom:1px solid var(--border)}
 body:not(.force-desktop) .panel-right{order:2;flex:1}
 .tab-btn{padding:6px 9px;font-size:11px}
}
</style></head><body class="desktop">
<header>
 <div class="hdr-top">
  <h1>Ethernet Tester</h1>
  <div class="hdr-btns">
   <select id="ri" onchange="setAuto()" title="Auto-refresh">
    <option value="0">Off</option><option value="1000">1s</option>
    <option value="2000" selected>2s</option><option value="5000">5s</option>
   </select>
   <button onclick="refresh()">&#8635;</button>
   <button onclick="openSettings()" title="Settings" style="background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.3);color:#fff">&#9881;</button>
   <button class="stop" onclick="reboot()" title="Reboot">&#9211;</button>
   <button id="layoutToggle" onclick="toggleLayout()">Mobile</button>
  </div>
 </div>
 <div class="hdr-stats" id="hdrStats">
  <span id="hsLink">Link: --</span><span id="hsMgmt">Mgmt: --</span>
  <span id="hsIP">Eth: --</span><span id="hsHeap">Heap: --</span>
  <span id="hsSd">SD: --</span><span id="hsUp">Up: --</span><span id="hsVer"></span>
 </div>
</header>
<div class="main">
 <div class="panel-left">
  <button class="toggle-out" onclick="toggleOutput()" id="outToggle" style="display:none">&#9660; Output</button>
  <div class="card" style="display:flex;flex-direction:column;height:100%;margin:0;padding:8px">
   <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
    <h2 style="margin:0">Output <span id="run"></span></h2>
    <div>
    <button style="padding:3px 8px;font-size:11px;background:#c62828;border:1px solid #a00;color:#fff" onclick="fetch('/api/abort',{method:'POST'})">Abort</button>
    <button style="padding:3px 8px;font-size:11px;background:var(--input);border:1px solid var(--border);color:var(--dim)" onclick="document.getElementById('log').textContent=''">Clear</button>
    </div>
   </div>
   <pre id="log">(run a command to see output here)</pre>
  </div>
 </div>
 <div class="panel-right">
  <div class="tabs" id="tabBar">
   <button class="tab-btn active" onclick="showTab('status')">Status</button>
   <button class="tab-btn" onclick="showTab('l1l2')">L1/L2</button>
   <button class="tab-btn" onclick="showTab('inject')">Inject</button>
   <button class="tab-btn" onclick="showTab('test')">Tests</button>
   <button class="tab-btn" onclick="showTab('recon')">Recon</button>
   <button class="tab-btn" onclick="showTab('security')">Security</button>
   <button class="tab-btn" onclick="showTab('files')">Files</button>
   <button class="tab-btn" onclick="showTab('scripts')">Scripts</button>
  </div>

  <!-- STATUS TAB -->
  <div class="tab-content active" id="tab-status">
   <div class="card"><h2>Device Status</h2>
    <table id="st"><tr><td>loading...</td></tr></table>
   </div>
   <div class="card"><h2>SD Card</h2>
    <div class="row">
     <button onclick="cmd('sd')">Info</button>
     <button onclick="cmd('sd init')">Re-init</button>
     <button class="stop" onclick="if(confirm('Erase ALL SD data?'))cmd('sd format')">Format</button>
    </div>
   </div>
  </div>

  <!-- L1/L2 TAB -->
  <div class="tab-content" id="tab-l1l2">
   <div class="card"><h2>PHY / Link Mode</h2>
    <div class="row">
     <select id="phymode" style="flex:2">
      <option value="auto">Auto-negotiate</option>
      <option value="100fd">100 Mbps Full-Duplex</option>
      <option value="100hd">100 Mbps Half-Duplex</option>
      <option value="10fd">10 Mbps Full-Duplex</option>
      <option value="10hd">10 Mbps Half-Duplex</option>
     </select>
     <button onclick="cmd('link speed '+v('phymode'))">Apply</button>
    </div>
   </div>
   <div class="card"><h2>Traffic</h2>
    <div class="row">
     <button onclick="cmd('stats')">Stats</button>
     <button class="warn" onclick="cmd('stats clear')">Clear</button>
     <button onclick="cmd('loopback on')">Loop on</button>
     <button class="stop" onclick="cmd('loopback off')">Loop off</button>
    </div>
    <div class="row">
     <input id="smac" placeholder="source MAC"><button onclick="cmd('mac '+v('smac'))">Set</button>
    </div>
    <div class="row">
     <input id="tmac" placeholder="target MAC"><button onclick="cmd('target '+v('tmac'))">Set</button>
    </div>
    <div class="row">
     <input id="scount" type="number" placeholder="count" value="100" style="width:6em">
     <input id="ssize" type="number" placeholder="size" value="64" style="width:5em">
     <button onclick="cmd('send '+v('scount')+' '+v('ssize'))">Send</button>
    </div>
   </div>
  </div>

  <!-- INJECTION TAB -->
  <div class="tab-content" id="tab-inject">
   <div class="card"><h2>Error Injection</h2>
    <div class="row">
     <button onclick="cmd('inject runt')">Runt</button>
     <button onclick="cmd('inject giant')">Giant</button>
     <button onclick="cmd('inject jumbo')">Jumbo</button>
     <button onclick="cmd('inject badtype')">BadType</button>
    </div>
    <div class="row">
     <button onclick="cmd('inject broadcast')">Broadcast</button>
     <button onclick="cmd('inject multicast')">Multicast</button>
     <button onclick="cmd('inject pause')">PAUSE</button>
    </div>
    <h3>Pattern</h3>
    <div class="row">
     <select id="ptype"><option>zeros</option><option>ones</option><option>alt</option><option>incr</option><option>random</option></select>
     <input id="plen" type="number" placeholder="len" value="64" style="width:5em">
     <input id="pn" type="number" placeholder="n" value="100" style="width:5em">
     <button onclick="cmd('inject pattern '+v('ptype')+' '+v('plen')+' '+v('pn'))">Inject</button>
    </div>
    <h3>Sustained</h3>
    <div class="row">
     <input id="srate" type="number" placeholder="Hz" value="1000" style="width:6em">
     <button class="warn" onclick="cmd('inject storm '+v('srate'))">Storm</button>
    </div>
    <div class="row">
     <select id="ctype"><option>giant</option><option>jumbo</option><option>badtype</option><option>broadcast</option><option>multicast</option><option>pause</option><option>pattern</option></select>
     <input id="crate" type="number" placeholder="fps" value="1000" style="width:5em">
     <button class="warn" onclick="cmd('inject continuous '+v('ctype')+' '+v('crate'))">Continuous</button>
    </div>
    <div class="row"><button class="stop" onclick="cmd('inject stop')">Stop all injection</button></div>
   </div>
  </div>

  <!-- TESTS TAB -->
  <div class="tab-content" id="tab-test">
   <div class="card"><h2>RFC 2544 (DUT loopback required)</h2>
    <div class="row">
     <input id="rsize" type="number" placeholder="frame size (blank=all)" style="width:8em">
    </div>
    <div class="row">
     <button onclick="cmd('test throughput '+v('rsize'))">Throughput</button>
     <button onclick="cmd('test latency '+v('rsize'))">Latency</button>
     <button onclick="cmd('test frameloss '+v('rsize'))">Frame Loss</button>
     <button onclick="cmd('test backtoback '+v('rsize'))">Back-to-Back</button>
    </div>
    <div class="row"><button class="warn" onclick="cmd('test all')">Full RFC 2544 Suite</button></div>
   </div>
   <div class="card"><h2>DHCP Tests</h2>
    <div class="row">
     <button onclick="cmd('dhcp discover')">DORA</button>
     <button onclick="cmd('dhcp detect')">Detect</button>
     <button class="warn" onclick="cmd('dhcp flood 50')">Starve</button>
    </div>
    <div class="row">
     <button class="warn" onclick="cmd('dhcp decline')">Decline</button>
     <button class="warn" onclick="cmd('dhcp nak')">NAK</button>
     <button class="warn" onclick="cmd('dhcp malformed')">Malform</button>
     <button class="warn" onclick="cmd('dhcp renew')">Renew</button>
    </div>
   </div>
   <div class="card"><h2>DNS</h2>
    <div class="row">
     <input id="dnshost" placeholder="hostname">
     <input id="dnssrv" placeholder="server (opt)" style="width:8em">
     <button onclick="cmd('dns resolve '+v('dnshost')+' '+v('dnssrv'))">Resolve</button>
    </div>
    <div class="row">
     <input id="host" placeholder="hostname.local">
     <button onclick="cmd('probe '+v('host'))">mDNS Probe</button>
    </div>
   </div>
   <div class="card" id="offensiveCard" style="display:none">
    <h2>Offensive <span id="offBadge" class="bad" style="font-size:11px">(ARMED)</span></h2>
    <h3>L2 Attacks</h3>
    <div class="row">
     <input id="vlvid" type="number" placeholder="VLAN" style="width:5em">
     <button class="warn" onclick="cmd('l2 vlan '+v('vlvid'))">VLAN</button>
     <input id="vldn" type="number" placeholder="native" style="width:5em">
     <input id="vldt" type="number" placeholder="target" style="width:5em">
     <button class="warn" onclick="cmd('l2 dtag '+v('vldn')+' '+v('vldt'))">Q-in-Q</button>
    </div>
    <div class="row">
     <button class="warn" onclick="cmd('l2 dtp')">DTP</button>
     <button class="warn" onclick="cmd('l2 macflood')">MAC flood</button>
     <button class="warn" onclick="cmd('l2 stp root')">STP root</button>
     <button class="warn" onclick="cmd('l2 lldpflood')">LLDP flood</button>
    </div>
    <h3>ARP / DHCP / IPv6 / DNS</h3>
    <div class="row">
     <input id="aspv" placeholder="victim"><input id="aspg" placeholder="gateway">
     <button class="warn" onclick="cmd('arp spoof '+v('aspv')+' '+v('aspg'))">ARP MITM</button>
    </div>
    <div class="row">
     <input id="dhrp" placeholder="pool IP">
     <button class="warn" onclick="cmd('dhcp rogue '+v('dhrp'))">Rogue DHCP</button>
     <button class="warn" onclick="cmd('ipv6 rogue')">Rogue RA</button>
    </div>
    <div class="row">
     <input id="dnsspoofip" placeholder="spoof IP">
     <button class="warn" onclick="cmd('dns spoof '+v('dnsspoofip'))">DNS spoof</button>
    </div>
    <div class="row">
     <input id="fhrpgrp" type="number" placeholder="grp" style="width:4em">
     <input id="fhrpvip" placeholder="virtual IP">
     <button class="warn" onclick="cmd('fhrp hsrp '+v('fhrpgrp')+' '+v('fhrpvip'))">HSRP</button>
     <button class="warn" onclick="cmd('fhrp vrrp '+v('fhrpgrp')+' '+v('fhrpvip'))">VRRP</button>
    </div>
    <h3>802.1X Attacks</h3>
    <div class="row">
     <button class="warn" onclick="cmd('dot1x startflood')">EAPOL flood</button>
     <input id="lofmac" placeholder="victim MAC">
     <button class="warn" onclick="cmd('dot1x logoffmac '+v('lofmac'))">Spoof Logoff</button>
     <button class="warn" onclick="cmd('dot1x rogue')">Rogue Auth</button>
    </div>
   </div>
  </div>

  <!-- RECON TAB -->
  <div class="tab-content" id="tab-recon">
   <div class="card"><h2>IP Configuration</h2>
    <div class="row">
     <button onclick="cmd('ip show')">Show</button>
     <button onclick="cmd('ip dhcp')">DHCP</button>
    </div>
    <div class="row">
     <input id="sip" placeholder="IP"><input id="smask" placeholder="mask"><input id="sgw" placeholder="gateway">
     <button onclick="cmd('ip static '+v('sip')+' '+v('smask')+' '+v('sgw'))">Static</button>
    </div>
   </div>
   <div class="card"><h2>Discovery (LLDP/CDP)</h2>
    <div class="row">
     <input id="dsec" type="number" placeholder="secs" value="65" style="width:5em">
     <button onclick="cmd('discover '+v('dsec'))">Listen</button>
     <button onclick="cmd('advertise lldp on')">LLDP on</button>
     <button onclick="cmd('advertise cdp on')">CDP on</button>
     <button class="stop" onclick="cmd('advertise off')">Off</button>
    </div>
   </div>
   <div class="card"><h2>Network Scan</h2>
    <div class="row">
     <input id="rsweepa" placeholder="start IP"><input id="rsweepb" placeholder="end IP">
    </div>
    <div class="row">
     <button onclick="if(document.getElementById('nsRandMac').checked)cmd('mac random');cmd('recon sweep '+v('rsweepa')+' '+v('rsweepb'))">Ping sweep</button>
     <button onclick="if(document.getElementById('nsRandMac').checked)cmd('mac random');cmd('arp scan '+v('rsweepa')+' '+v('rsweepb'))">ARP scan</button>
    </div>
    <div class="row">
     <input id="rtrace" placeholder="target IP">
     <button onclick="if(document.getElementById('nsRandMac').checked)cmd('mac random');cmd('recon trace '+v('rtrace'))">Traceroute</button>
     <input id="rpsecs" type="number" value="30" style="width:5em">
     <button onclick="cmd('recon passive '+v('rpsecs'))">Passive</button>
    </div>
    <div class="row" style="gap:12px">
     <label style="font-size:12px"><input type="checkbox" id="nsRandMac" style="width:auto"> Random src MAC</label>
    </div>
   </div>
   <div class="card"><h2>Port Scanner</h2>
    <div class="row">
     <input id="scnip" placeholder="target IP">
     <button onclick="if(document.getElementById('psRandMac').checked)cmd('mac random');cmd('scan common '+v('scnip'))">Common ports</button>
    </div>
    <div class="row">
     <input id="scnp1" type="number" placeholder="first" style="width:5em">
     <input id="scnp2" type="number" placeholder="last" style="width:5em">
     <button onclick="if(document.getElementById('psRandMac').checked)cmd('mac random');cmd('scan ports '+v('scnip')+' '+v('scnp1')+' '+v('scnp2'))">Range</button>
    </div>
    <div class="row">
     <input id="scnbp" type="number" placeholder="port" style="width:5em">
     <button onclick="if(document.getElementById('psRandMac').checked)cmd('mac random');cmd('scan banner '+v('scnip')+' '+v('scnbp'))">Banner</button>
    </div>
    <div class="row" style="gap:12px">
     <label style="font-size:12px"><input type="checkbox" id="psRandMac" style="width:auto"> Random src MAC</label>
    </div>
   </div>
   <div class="card"><h2>Network Assessment</h2>
    <div class="row">
     <input id="asRange" placeholder="CIDR or start IP" style="width:10em">
     <input id="asEnd" placeholder="end IP (if not CIDR)" style="width:10em">
    </div>
    <div class="row">
     <input id="asPorts" placeholder="ports (default: 21,22,80,443)" style="width:14em">
    </div>
    <div class="row" style="gap:12px">
     <label style="font-size:12px"><input type="checkbox" id="asRand" style="width:auto" checked> Randomize order</label>
     <label style="font-size:12px"><input type="checkbox" id="asMac" style="width:auto"> Random MAC per host</label>
    </div>
    <div class="row">
     <button class="warn" onclick="let r=v('asRange'),e=v('asEnd'),p=v('asPorts'),f='';if(document.getElementById('asRand').checked)f+=' -r';if(document.getElementById('asMac').checked)f+=' -m';cmd('assess '+r+(e?' '+e:'')+(p?' '+p:'')+f)">Run Assessment</button>
    </div>
   </div>
   <div class="card"><h2>Protocol Listeners</h2>
    <div class="row">
     <button onclick="cmd('link')">Link Info</button>
     <button onclick="cmd('link monitor')">Monitor</button>
     <button onclick="cmd('wifi scan')">WiFi scan</button>
    </div>
    <div class="row">
     <button onclick="cmd('ipv6 listen')">IPv6 NDP</button>
     <button onclick="cmd('fhrp listen')">FHRP</button>
     <button onclick="cmd('dhcpv6 probe')">DHCPv6</button>
    </div>
    <div class="row">
     <input id="snmpip" placeholder="target IP">
     <button onclick="cmd('snmp probe '+v('snmpip'))">SNMP</button>
     <input id="snmprange" placeholder="end IP" style="width:8em">
     <button onclick="cmd('snmp sweep '+v('snmpip')+' '+v('snmprange'))">Sweep</button>
    </div>
   </div>
  </div>

  <!-- SECURITY TAB -->
  <div class="tab-content" id="tab-security">
   <div class="card"><h2>802.1X / EAP</h2>
    <div class="row">
     <select id="d1xmethod" onchange="cmd('dot1x method '+v('d1xmethod'))">
      <option value="md5">MD5</option><option value="peap">PEAP</option>
      <option value="ttls-pap">TTLS/PAP</option><option value="ttls-mschap">TTLS/MSCHAPv2</option>
      <option value="tls">TLS</option>
     </select>
     <button onclick="if(document.getElementById('d1xRandMac').checked)cmd('mac random');cmd('dot1x probe')">Probe</button>
     <button onclick="if(document.getElementById('d1xRandMac').checked)cmd('mac random');cmd('dot1x auth')">Auth</button>
     <button class="stop" onclick="cmd('dot1x logoff')">Logoff</button>
    </div>
    <div class="row">
     <input id="d1xtgtmac" placeholder="target MAC (or PAE mcast)" style="width:11em">
     <input id="d1xtgtip" placeholder="target IP" style="width:8em">
     <button onclick="let m=v('d1xtgtmac'),i=v('d1xtgtip');if(m)cmd('dot1x target '+m);if(i)cmd('dot1x target '+i)">Set Target</button>
     <button class="stop" onclick="cmd('dot1x target clear')">Clear</button>
    </div>
    <div class="row">
     <input id="d1xuser" placeholder="identity"><button onclick="cmd('dot1x user '+v('d1xuser'))">Set</button>
    </div>
    <div class="row">
     <input id="d1xpass" type="password" placeholder="password"><button onclick="cmd('dot1x pass '+v('d1xpass'))">Set</button>
    </div>
    <div class="row" style="gap:12px">
     <label style="font-size:12px"><input type="checkbox" id="d1xRandMac" style="width:auto"> Random src MAC</label>
    </div>
    <h3>Certificates</h3>
    <div class="row">
     <input type="file" id="caf" accept=".pem,.crt"><button onclick="upCert('ca','caf')">CA</button>
     <input type="file" id="clf" accept=".pem,.crt"><button onclick="upCert('client','clf')">Cert</button>
    </div>
    <div class="row">
     <input type="file" id="kyf" accept=".pem,.key"><button onclick="upCert('key','kyf')">Key</button>
     <button class="stop" onclick="if(confirm('Clear all certs?'))cmd('dot1x cert clear all')">Clear</button>
    </div>
    <table id="certst" style="font-size:12px"><tr><td>loading...</td></tr></table>
   </div>
  </div>


  <!-- FILES TAB -->
  <div class="tab-content" id="tab-files">
   <div class="card"><h2>PCAP Capture</h2>
    <div class="row">
     <input id="pcsecs" type="number" value="10" style="width:5em" placeholder="secs">
     <input id="pcmax" type="number" placeholder="max frames" style="width:7em">
     <button onclick="cmd('pcap start '+v('pcsecs')+' '+(v('pcmax')||'0'))">Capture</button>
    </div>
    <div class="row">
     <button onclick="cmd('pcap status')">Status</button>
     <a href="/capture.pcap"><button type="button">Download .pcap</button></a>
     <button class="stop" onclick="cmd('pcap delete')">Delete</button>
    </div>
   </div>
   <div class="card"><h2>SD Card File Browser</h2>
    <div class="row">
     <input id="fpath" placeholder="path" value="/">
     <button onclick="cmd('sd ls '+v('fpath'))">List</button>
     <button onclick="cmd('sd cat '+v('fpath'))">View</button>
    </div>
    <div class="row">
     <input id="frm" placeholder="file to delete">
     <button class="stop" onclick="cmd('sd rm '+v('frm'))">Delete</button>
    </div>
    <div class="row">
     <input id="fren1" placeholder="old path" style="flex:1">
     <input id="fren2" placeholder="new path" style="flex:1">
     <button onclick="cmd('sd rename '+v('fren1')+' '+v('fren2'))">Rename</button>
    </div>
    <div class="row">
     <input id="fmkd" placeholder="directory path">
     <button onclick="cmd('sd mkdir '+v('fmkd'))">Mkdir</button>
    </div>
   </div>
   <div class="card"><h2>Logs</h2>
    <div class="row">
     <button onclick="cmd('log')">Status</button>
     <input id="logname" placeholder="log name (optional)">
     <button onclick="cmd('log start '+v('logname'))">Start</button>
     <button class="stop" onclick="cmd('log stop')">Stop</button>
    </div>
    <div class="row">
     <button onclick="cmd('log list')">List logs</button>
     <input id="logdel" placeholder="filename to delete">
     <button class="stop" onclick="cmd('log delete '+v('logdel'))">Delete</button>
    </div>
   </div>
  </div>

  <!-- SCRIPTS TAB -->
  <div class="tab-content" id="tab-scripts">
   <div class="card"><h2>Script Engine</h2>
    <div class="row">
     <button onclick="cmd('script')">Status</button>
     <button onclick="cmd('script list')">List scripts</button>
     <button class="stop" onclick="cmd('script stop')">Stop</button>
    </div>
    <h3>Run Script</h3>
    <div class="row">
     <input id="scrfile" placeholder="filename (in /scripts/)">
     <input id="scrlog" placeholder="log name (opt)" style="width:8em">
     <button onclick="cmd('script run '+v('scrfile')+' '+v('scrlog'))">Run</button>
    </div>
    <h3>Create Script</h3>
    <div class="row">
     <input id="scrnew" placeholder="new_script.txt">
     <button onclick="cmd('script create '+v('scrnew'))">Create template</button>
    </div>
    <h3>Quick Script (run inline)</h3>
    <textarea id="scrtext" placeholder="# One command per line&#10;echo Hello&#10;status&#10;delay 1000&#10;discover 10"></textarea>
    <div class="row">
     <button onclick="cmdInlineScript()">Run inline</button>
    </div>
   </div>
   <div class="card"><h2>Cron Scheduler</h2>
    <div class="row">
     <button onclick="cmd('cron')">List</button>
     <button onclick="cmd('cron reload')">Reload</button>
     <button class="stop" onclick="if(confirm('Clear all cron entries?'))cmd('cron clear')">Clear</button>
    </div>
    <h3>Add Entry</h3>
    <div class="row">
     <input id="cronmin" placeholder="min" value="*" style="width:3em">
     <input id="cronhr" placeholder="hr" value="*" style="width:3em">
     <input id="crondom" placeholder="dom" value="*" style="width:3em">
     <input id="cronmon" placeholder="mon" value="*" style="width:3em">
     <input id="crondow" placeholder="dow" value="*" style="width:3em">
    </div>
    <div class="row">
     <input id="croncmd" placeholder="command or /scripts/file.txt">
     <button onclick="cmd('cron add '+v('cronmin')+' '+v('cronhr')+' '+v('crondom')+' '+v('cronmon')+' '+v('crondow')+' '+v('croncmd'))">Add</button>
    </div>
    <div class="row">
     <input id="cronrm" type="number" placeholder="index #" style="width:5em">
     <button class="stop" onclick="cmd('cron remove '+v('cronrm'))">Remove</button>
    </div>
   </div>
   <div class="card"><h2>Script Language Reference</h2>
    <details><summary style="cursor:pointer;color:var(--dim);font-size:12px">Show directives</summary>
    <pre style="font-size:11px;margin-top:6px;max-height:200px"># Comment
delay 500            Pause N milliseconds
wait 2               Pause N seconds
echo message         Print message
set VAR value        Set variable ($VAR to use)
log start [name]     Start output logging
log stop             Stop logging
if_time HH:MM-HH:MM Skip if outside window
if_day MON,TUE,...   Skip if not matching day
repeat N             Repeat block N times
end_repeat           End repeat block
upload log name url  Upload log file
upload pcap url      Upload pcap
rm /path/file        Delete SD file
rename old new       Rename SD file
mkdir /path          Create directory
write_file path text Append to file
abort                Stop script
(any other line)     Run as CLI command</pre>
    </details>
   </div>
  </div>

 </div>
</div>
<!-- Settings Modal -->
<div class="modal-overlay" id="settingsModal" onclick="if(event.target===this)closeSettings()">
 <div class="modal">
  <button class="modal-close" onclick="closeSettings()">&#10005;</button>
  <h2 style="margin-top:0">System</h2>
  <div class="row">
   <button onclick="cmd('status')">Full status</button>
   <button onclick="cmd('help')">CLI help</button>
   <button class="stop" onclick="reboot()">Reboot</button>
  </div>
  <div class="row" style="gap:12px">
   <label style="font-size:12px"><input type="checkbox" id="cfgRandMac" style="width:auto" onchange="cmd('mac autorand '+(this.checked?'on':'off'))"> Auto-randomize src MAC</label>
  </div>
  <h2>Offensive Mode</h2>
  <div class="row">
   <button class="warn" onclick="armDevice()">Arm</button>
   <button class="stop" onclick="disarmDevice()">Disarm</button>
   <span id="armStatus" style="font-size:12px;color:var(--dim);padding:6px">--</span>
  </div>
  <h2>Wi-Fi (reboot to apply)</h2>
  <label style="font-size:12px"><input id="wen" type="checkbox" style="width:auto"> Wi-Fi enabled</label>
  <select id="wmode" onchange="modeUi()" style="margin:4px 0">
   <option value="sta">Station (join network)</option><option value="ap">Access Point</option>
  </select>
  <div id="stacfg">
   <div class="row"><input id="ssid" placeholder="SSID"><input id="pass" type="password" placeholder="password"></div>
  </div>
  <div id="apcfg" style="display:none">
   <div class="row"><input id="apssid" placeholder="AP SSID"><input id="appass" type="password" placeholder="AP password"></div>
  </div>
  <div class="row"><input id="hn" placeholder="hostname"><button onclick="saveCfg()">Save</button></div>
  <h2>Web Server</h2>
  <div class="row">
   <button onclick="cmd('web')">Status</button>
   <button onclick="cmd('web on')">Start</button>
   <button class="stop" onclick="cmd('web off')">Stop</button>
  </div>
  <div class="row">
   <button onclick="cmd('web https on')">HTTPS On</button>
   <button class="stop" onclick="cmd('web https off')">HTTPS Off</button>
  </div>
  <h2>Web Authentication</h2>
  <div class="row">
   <input id="wauser" placeholder="username">
   <input id="wapass" type="password" placeholder="password">
   <button onclick="cmd('web auth set '+v('wauser')+' '+v('wapass'))">Set</button>
  </div>
  <div class="row">
   <button class="stop" onclick="cmd('web auth clear')">Clear auth</button>
  </div>
  <h2>WireGuard VPN</h2>
  <div class="row">
   <button onclick="cmd('wg')">Status</button>
   <button onclick="cmd('wg start')">Start</button>
   <button class="stop" onclick="cmd('wg stop')">Stop</button>
  </div>
  <div class="row">
   <input id="wgip" placeholder="tunnel IP (10.0.0.2)">
   <button onclick="cmd('wg set localip '+v('wgip'))">Set</button>
  </div>
  <div class="row">
   <input id="wgep" placeholder="endpoint host/IP">
   <input id="wgport" type="number" placeholder="port" value="51820" style="width:6em">
   <button onclick="cmd('wg set endpoint '+v('wgep'));cmd('wg set port '+v('wgport'))">Set</button>
  </div>
  <div class="row">
   <input id="wgpriv" type="password" placeholder="private key (base64)">
   <button onclick="cmd('wg set privkey '+v('wgpriv'))">Set</button>
  </div>
  <div class="row">
   <input id="wgpub" placeholder="peer public key (base64)">
   <button onclick="cmd('wg set pubkey '+v('wgpub'))">Set</button>
  </div>
  <div class="row">
   <input id="wgpsk" type="password" placeholder="pre-shared key (optional)">
   <button onclick="cmd('wg set psk '+v('wgpsk'))">Set</button>
  </div>
  <div class="row">
   <button onclick="cmd('wg enable')">Enable</button>
   <button class="stop" onclick="cmd('wg disable')">Disable</button>
   <button class="stop" onclick="if(confirm('Erase WG config?'))cmd('wg clear')">Clear</button>
  </div>
  <div class="row">
   <button onclick="cmd('wg set weboff on')">Web off when VPN</button>
   <button class="stop" onclick="cmd('wg set weboff off')">Keep web on</button>
  </div>
  <h2>Upload Destination</h2>
  <div class="row">
   <button onclick="cmd('upload')">Show config</button>
  </div>
  <div class="row">
   <input id="upurl" placeholder="https://server/upload">
   <input id="upuser" placeholder="user" style="width:5em">
   <input id="uppass" type="password" placeholder="pass" style="width:5em">
   <button onclick="cmd('upload set '+v('upurl')+' '+v('upuser')+' '+v('uppass'))">Save</button>
  </div>
  <div class="row">
   <input id="uplf" placeholder="log filename">
   <button onclick="cmd('upload log '+v('uplf'))">Upload log</button>
   <button onclick="cmd('upload pcap')">Upload pcap</button>
  </div>
  <h2>Firmware Update (OTA)</h2>
  <div class="row">
   <input type="file" id="otaFile" accept=".bin" style="font-size:12px;color:var(--dim)">
   <button class="warn" onclick="otaUpload()">Flash</button>
  </div>
  <div class="row">
   <input id="otaTftp" placeholder="TFTP server IP">
   <input id="otaFn" placeholder="firmware.bin" style="width:10em">
   <button class="warn" onclick="cmd('ota tftp '+v('otaTftp')+' '+(v('otaFn')||'firmware.bin'))">TFTP Update</button>
  </div>
  <div id="otaProg" style="font-size:11px;color:var(--dim);margin-top:4px"></div>
 </div>
</div>
<script>
function v(i){return document.getElementById(i).value}
let polling=false, armed=false;
function openSettings(){document.getElementById('settingsModal').classList.add('show');}
function closeSettings(){document.getElementById('settingsModal').classList.remove('show');}
function otaUpload(){
 let f=document.getElementById('otaFile').files[0];
 if(!f){alert('Select a .bin firmware file first.');return;}
 if(!confirm('Flash new firmware? Device will reboot on success.'))return;
 let prog=document.getElementById('otaProg');
 prog.textContent='Uploading...';
 let fd=new FormData();fd.append('file',f,f.name);
 let xhr=new XMLHttpRequest();
 xhr.open('POST','/api/ota',true);
 xhr.withCredentials=true;
 xhr.timeout=120000;
 xhr.upload.onprogress=function(e){if(e.lengthComputable)prog.textContent='Uploading: '+Math.round(e.loaded/e.total*100)+'%';};
 xhr.onload=function(){prog.textContent=xhr.responseText;if(xhr.status===200)setTimeout(()=>location.reload(),5000);};
 xhr.onerror=function(){prog.textContent='Upload failed (network error). Check device connection.';};
 xhr.ontimeout=function(){prog.textContent='Upload timed out.';};
 xhr.send(fd);
}
function armDevice(){
 if(!confirm('Enable offensive mode? For authorized lab use only.'))return;
 cmd('arm on');armed=true;updateArmUi();
}
function disarmDevice(){cmd('disarm');armed=false;updateArmUi();}
function updateArmUi(){
 document.getElementById('offensiveCard').style.display=armed?'block':'none';
 document.getElementById('armStatus').textContent=armed?'ARMED':'disarmed';
 document.getElementById('armStatus').style.color=armed?'var(--bad)':'var(--dim)';
}
function showTab(name){
 document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));
 document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
 document.getElementById('tab-'+name).classList.add('active');
 document.querySelector('[onclick="showTab(\''+name+'\')"]').classList.add('active');
 localStorage.setItem('lastTab',name);
}
function detectLayout(){
 let force=localStorage.getItem('forceDesktop');
 if(force==='1'){document.body.className='desktop force-desktop';document.getElementById('layoutToggle').textContent='Mobile';return;}
 if(window.innerWidth<900){document.body.className='mobile';document.getElementById('layoutToggle').textContent='Desktop';
  document.getElementById('outToggle').style.display='block';}
 else{document.body.className='desktop';document.getElementById('layoutToggle').textContent='Mobile';
  document.getElementById('outToggle').style.display='none';}
}
function toggleLayout(){
 let isD=document.body.classList.contains('desktop')||document.body.classList.contains('force-desktop');
 if(isD){document.body.className='mobile';localStorage.removeItem('forceDesktop');document.getElementById('layoutToggle').textContent='Desktop';document.getElementById('outToggle').style.display='block';}
 else{document.body.className='desktop force-desktop';localStorage.setItem('forceDesktop','1');document.getElementById('layoutToggle').textContent='Mobile';document.getElementById('outToggle').style.display='none';}
}
function toggleOutput(){let p=document.querySelector('.panel-left');p.classList.toggle('collapsed');
 document.getElementById('outToggle').textContent=p.classList.contains('collapsed')?'\u25B6 Output':'\u25BC Output';}
function setRun(r){document.getElementById('run').innerHTML=r?'<span style="color:#d29922">\u25CF running</span>':'<span class="ok">\u25CF done</span>';}
function poll(){fetch('/api/result').then(r=>r.json()).then(s=>{
 let log=document.getElementById('log');log.textContent=s.output||'(no output)';log.scrollTop=log.scrollHeight;
 setRun(s.running);if(s.running)setTimeout(poll,600);else polling=false;
}).catch(()=>{polling=false;});}
function cmd(c){
 fetch('/api/cmd',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'c='+encodeURIComponent(c)})
 .then(r=>{if(r.status==409)return r.text().then(t=>{document.getElementById('run').innerHTML='<span class="bad">'+t+'</span>';});
  document.getElementById('log').textContent='running: '+c+' ...';setRun(true);
  if(!polling){polling=true;setTimeout(poll,300);}});}
function cmdInlineScript(){
 let text=document.getElementById('scrtext').value;
 let lines=text.split('\n');
 // Chain commands with delays between
 let i=0;
 function next(){
  if(i>=lines.length)return;
  let l=lines[i++].trim();
  if(!l||l.startsWith('#')){next();return;}
  cmd(l);
  // Wait for completion then next
  let check=()=>{if(polling)setTimeout(check,500);else{setTimeout(next,200);}};
  setTimeout(check,500);
 }
 next();
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
 document.getElementById('log').textContent='Rebooting...';cmd('reboot');}
function refresh(){fetch('/api/status').then(r=>r.json()).then(s=>{
 let link=s.link||'--',spd=(s.speed||'--')+' '+(s.duplex||'');
 document.getElementById('hsLink').innerHTML='Link: <b class="'+(link=='UP'?'ok':'bad')+'">'+link+'</b> '+spd;
 document.getElementById('hsMgmt').textContent='Mgmt: '+location.hostname;
 document.getElementById('hsIP').textContent='Eth: '+(s.ip||'--');
 let heapK=s.heap_free?Math.round(s.heap_free/1024)+'K':'--';
 document.getElementById('hsHeap').textContent='Heap: '+heapK;
 if(s.sd_present)document.getElementById('hsSd').innerHTML='SD: <b class="ok">'+(s.sd_used_mb||0)+'/'+(s.sd_total_mb||0)+' MB</b>';
 else document.getElementById('hsSd').innerHTML='SD: <span class="bad">none</span>';
 let up=s.uptime_s||0,um=Math.floor(up/60),uh=Math.floor(um/60);
 document.getElementById('hsUp').textContent='Up: '+(uh?uh+'h ':'')+(um%60)+'m';
 document.getElementById('hsVer').textContent='v'+s.version;
 const labels={link:'Link',speed:'Speed',duplex:'Duplex',mac:'MAC',ip:'Eth IP',mask:'Mask',gateway:'Gateway',
  tx_frames:'TX frames',rx_frames:'RX frames',tx_errors:'TX errors',rx_dropped:'RX dropped',
  storm:'Storm',continuous:'Continuous',heap_free:'Heap free',heap_min:'Heap min',
  psram_free:'PSRAM free',uptime_s:'Uptime (s)',sd_present:'SD card',sd_total_mb:'SD total (MB)',
  sd_used_mb:'SD used (MB)',fs_total_kb:'Flash FS total (KB)',fs_used_kb:'Flash FS used (KB)',pcap_size:'PCAP file (B)',version:'Version'};
 let h='';for(let k in s){let val=s[k],lbl=labels[k]||k;
  if(k=='link')val='<span class="'+(val=='UP'?'ok':'bad')+'">'+val+'</span>';
  if(k=='sd_present')val=val?'<span class="ok">yes</span>':'<span class="bad">no</span>';
  h+='<tr><td>'+lbl+'</td><td>'+val+'</td></tr>';}
 document.getElementById('st').innerHTML=h;}).catch(()=>{});}
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
 if(c.hasPass)document.getElementById('pass').placeholder='(set)';
 if(c.apHasPass)document.getElementById('appass').placeholder='(set)';
 var rm=!!c.randmac;
 document.getElementById('cfgRandMac').checked=rm;
 document.getElementById('nsRandMac').checked=rm;
 document.getElementById('psRandMac').checked=rm;
 document.getElementById('d1xRandMac').checked=rm;
 document.getElementById('asRand').checked=document.getElementById('asRand').checked;
 if(rm)document.getElementById('asMac').checked=true;
 modeUi();}).catch(()=>{});}
function refreshCerts(){fetch('/api/cert').then(r=>r.json()).then(c=>{
 document.getElementById('d1xmethod').value=c.method||'md5';
 let row=(n,o)=>'<tr><td>'+n+'</td><td>'+(o.present?'<span class="ok">'+o.bytes+'B</span>':'<span class="bad">none</span>')+'</td></tr>';
 document.getElementById('certst').innerHTML=row('CA',c.ca)+row('Client',c.client)+row('Key',c.key);
}).catch(()=>{});}
function upCert(kind,inp){let f=document.getElementById(inp).files[0];
 if(!f){alert('Choose a PEM file first.');return;}
 let fd=new FormData();fd.append('f',f,f.name);
 document.getElementById('log').textContent='Uploading '+kind+'...';
 fetch('/api/cert/'+kind,{method:'POST',body:fd})
  .then(r=>r.text()).then(t=>{document.getElementById('log').textContent=t;refreshCerts();})
  .catch(e=>{document.getElementById('log').textContent='Upload failed: '+e;});}
// Restore last tab
let lt=localStorage.getItem('lastTab');if(lt)showTab(lt);
detectLayout();window.addEventListener('resize',()=>{if(!document.body.classList.contains('force-desktop'))detectLayout();});
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
        MDNS.addService("https", "tcp", 443);
        MDNS.addService("http", "tcp", 80);
        Serial.printf("mDNS: %s.local\r\n", _hostname);
    }

    // Load auth credentials from NVS (defaults: admin/admin, HTTPS on)
    _loadAuth();

    // Always start HTTP on port 80 (has full API routes)
    AsyncWebServer *srv = new AsyncWebServer(80);
    _server = srv;
    _routes();
    _applyAuth();
    srv->begin();
    _serverRunning = true;
    Serial.println("Web: HTTP server started on port 80 (basic auth enforced).");
}

// =============================================================================
// Stop / Start web server (Wi-Fi stays up)
// =============================================================================
void WebControl::stopServer()
{
    if (!_serverRunning) return;
    _stopHttps();
    if (_server) {
        AsyncWebServer *srv = static_cast<AsyncWebServer *>(_server);
        srv->end();
    }
    _serverRunning = false;
    Serial.println("Web: server stopped.");
}

void WebControl::startServer()
{
    if (_serverRunning) { Serial.println("Web: server already running."); return; }
    if (_server) {
        AsyncWebServer *srv = static_cast<AsyncWebServer *>(_server);
        srv->begin();
    }
    if (_httpsEnabled) _startHttps();
    _serverRunning = true;
    Serial.println("Web: server started.");
}

// =============================================================================
// Authentication (NVS-backed)
// =============================================================================
void WebControl::_loadAuth()
{
    Preferences prefs;
    prefs.begin(WEB_AUTH_NVS_NS, true);
    String u = prefs.getString("user", "admin");
    String p = prefs.getString("pass", "admin");
    _httpsEnabled = prefs.getBool("https", true);
    prefs.end();
    strlcpy(_authUser, u.c_str(), sizeof(_authUser));
    strlcpy(_authPass, p.c_str(), sizeof(_authPass));
    _authEnabled = (_authUser[0] != '\0' && _authPass[0] != '\0');
}

void WebControl::setAuthCredentials(const char *user, const char *pass)
{
    strlcpy(_authUser, user, sizeof(_authUser));
    strlcpy(_authPass, pass, sizeof(_authPass));
    _authEnabled = (_authUser[0] != '\0' && _authPass[0] != '\0');
    Preferences prefs;
    prefs.begin(WEB_AUTH_NVS_NS, false);
    prefs.putString("user", _authUser);
    prefs.putString("pass", _authPass);
    prefs.end();
    _applyAuth();
}

void WebControl::clearAuth()
{
    _authUser[0] = '\0';
    _authPass[0] = '\0';
    _authEnabled = false;
    Preferences prefs;
    prefs.begin(WEB_AUTH_NVS_NS, false);
    prefs.remove("user");
    prefs.remove("pass");
    prefs.end();
    _applyAuth();
}

void WebControl::_applyAuth()
{
    // Sync auth to HTTPS server
    httpsSetAuth(_authEnabled ? _authUser : "", _authEnabled ? _authPass : "");

    if (!_server) return;
    AsyncWebServer *srv = static_cast<AsyncWebServer *>(_server);
    // Use a static middleware instance that persists for the server lifetime
    static AsyncAuthenticationMiddleware authMw;
    if (_authEnabled) {
        authMw.setUsername(_authUser);
        authMw.setPassword(_authPass);
        authMw.setRealm("Ethernet Tester");
        authMw.setAuthFailureMessage("Authentication required");
        authMw.setAuthType(AsyncAuthType::AUTH_BASIC);
        srv->addMiddleware(&authMw);
        Serial.printf("Web: basic auth enabled (user: %s)\r\n", _authUser);
    } else {
        authMw.setAuthType(AsyncAuthType::AUTH_NONE);
        Serial.println("Web: auth disabled (open access).");
    }
}

void WebControl::enableHttps(bool enable)
{
    _httpsEnabled = enable;
    Preferences prefs;
    prefs.begin(WEB_AUTH_NVS_NS, false);
    prefs.putBool("https", enable);
    prefs.end();
    if (enable && _serverRunning) {
        _startHttps();
    } else if (!enable) {
        _stopHttps();
    }
}

// =============================================================================
// HTTPS server (delegated to https_srv.cpp to avoid header conflicts)
// =============================================================================
void WebControl::_startHttps()
{
    if (_httpsHandle) return;
    httpsSetStatusProvider(_statusFn);
    httpsSetAuth(_authEnabled ? _authUser : "", _authEnabled ? _authPass : "");
    if (httpsStart(INDEX_HTML)) {
        _httpsHandle = (void *)1;  // non-null sentinel
    }
}

void WebControl::_stopHttps()
{
    if (!_httpsHandle) return;
    httpsStop();
    _httpsHandle = nullptr;
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

    srv->on("/api/abort", HTTP_POST, [this](AsyncWebServerRequest *req) {
        if (s_running) {
            Out.requestAbort();
            req->send(200, "text/plain", "abort requested");
        } else {
            req->send(200, "text/plain", "nothing running");
        }
    });

    srv->on("/api/ota", HTTP_POST,
        [](AsyncWebServerRequest *req) {
            if (Update.hasError()) {
                req->send(500, "text/plain", String("OTA failed: ") + Update.errorString());
            } else {
                req->send(200, "text/plain", "OTA success! Rebooting...");
                // Delay restart so the response can be sent
                static esp_timer_handle_t rst_timer = nullptr;
                if (!rst_timer) {
                    esp_timer_create_args_t args = {};
                    args.callback = [](void *) { ESP.restart(); };
                    args.name = "ota_rst";
                    esp_timer_create(&args, &rst_timer);
                }
                esp_timer_start_once(rst_timer, 1500000);  // 1.5 s
            }
        },
        [](AsyncWebServerRequest *req, const String &fn, size_t index,
           uint8_t *data, size_t len, bool final) {
            if (index == 0) {
                // Disable task watchdog for this core during flash writes
                esp_task_wdt_delete(NULL);
                if (!Update.begin(UPDATE_SIZE_UNKNOWN, U_FLASH)) {
                    Update.printError(Serial);
                }
            }
            if (!Update.hasError() && len) {
                if (Update.write(data, len) != len) {
                    Update.printError(Serial);
                }
            }
            if (final) {
                if (!Update.end(true)) {
                    Update.printError(Serial);
                }
                // Re-enable watchdog
                esp_task_wdt_add(NULL);
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
        json += ",\"randmac\":";        json += (_cfgLive && _cfgLive->randomMacDefault) ? "true" : "false";
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
