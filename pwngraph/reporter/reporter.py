"""Reporter — pyvis interactive graph + HTML severity report + trace dump."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

import networkx as nx
from jinja2 import Environment, FileSystemLoader, select_autoescape

from pwngraph.types import AttackPath, EdgeType, Finding, NodeType, TraceEvent

_CANARY_RE = re.compile(r"\bPWN-[A-F0-9]{8}\b")


# ---------------------------------------------------------------------------
# Injected interactive control surface for the pyvis graph.
#
# Self-contained HTML/CSS/JS (no extra runtime deps). It hooks the globals
# pyvis emits (`network`, `nodes`, `edges`) once they exist and layers on the
# six BloodHound-style features. Kept as one module constant so the renderer
# stays readable.
# ---------------------------------------------------------------------------
_GRAPH_UI = r'''
<style>
  :root{
    --bg:#0D1117; --panel:#161b22; --border:#30363d; --text:#E6EDF3;
    --muted:#8b949e; --accent:#FF2E63; --blue:#58a6ff;
  }
  html,body{margin:0;padding:0;background:var(--bg);}
  .card{border:none!important;background:var(--bg)!important;margin:0!important;}
  #mynetwork{height:100vh!important;border:none!important;background:var(--bg)!important;}
  #pwn-topbar{
    position:fixed;top:0;left:0;right:0;height:52px;display:flex;align-items:center;
    gap:10px;padding:0 16px;background:rgba(22,27,34,0.92);backdrop-filter:blur(8px);
    border-bottom:1px solid var(--border);z-index:10000;
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
  }
  #pwn-topbar .brand{font-weight:700;color:var(--text);font-size:15px;letter-spacing:.3px;margin-right:6px;}
  #pwn-topbar .brand span{color:var(--accent);}
  #pwn-search{
    flex:0 0 230px;background:var(--bg);border:1px solid var(--border);border-radius:6px;
    color:var(--text);padding:6px 10px;font-size:13px;outline:none;
  }
  #pwn-search:focus{border-color:var(--blue);}
  .pwn-btn{
    background:var(--panel);border:1px solid var(--border);color:var(--text);border-radius:6px;
    padding:6px 12px;font-size:12px;cursor:pointer;font-family:inherit;white-space:nowrap;
  }
  .pwn-btn:hover{border-color:var(--blue);color:var(--blue);}
  .pwn-btn.active{background:var(--accent);border-color:var(--accent);color:#fff;}
  .pwn-spacer{flex:1;}
  #pwn-sidebar{
    position:fixed;top:52px;right:0;width:340px;bottom:0;background:var(--panel);
    border-left:1px solid var(--border);transform:translateX(100%);transition:transform .22s ease;
    z-index:9999;overflow-y:auto;color:var(--text);
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
  }
  #pwn-sidebar.open{transform:translateX(0);}
  #pwn-sidebar .sb-head{padding:16px;border-bottom:1px solid var(--border);}
  #pwn-sidebar .sb-type{font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);}
  #pwn-sidebar .sb-title{font-size:18px;font-weight:700;margin-top:4px;word-break:break-word;}
  #pwn-sidebar .sb-body{padding:16px;}
  #pwn-sidebar .kv{display:flex;justify-content:space-between;gap:10px;padding:7px 0;border-bottom:1px solid #21262d;font-size:13px;}
  #pwn-sidebar .kv .k{color:var(--muted);}
  #pwn-sidebar .kv .v{text-align:right;word-break:break-word;}
  #pwn-sidebar pre{
    background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:10px;
    font-size:11px;white-space:pre-wrap;word-break:break-word;max-height:240px;overflow:auto;
    color:#c9d1d9;margin-top:6px;
  }
  .sb-badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:700;text-transform:uppercase;}
  .sb-close{float:right;cursor:pointer;color:var(--muted);font-size:20px;line-height:1;}
  .sb-close:hover{color:var(--text);}
  #pwn-findings{
    position:fixed;top:52px;left:0;width:320px;bottom:0;background:var(--panel);
    border-right:1px solid var(--border);transform:translateX(-100%);transition:transform .22s ease;
    z-index:9999;overflow-y:auto;color:var(--text);
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
  }
  #pwn-findings.open{transform:translateX(0);}
  #pwn-findings .fd-head{padding:14px 16px;border-bottom:1px solid var(--border);font-weight:700;font-size:14px;display:flex;justify-content:space-between;align-items:center;}
  #pwn-findings .fd-head .sb-close{float:none;}
  #pwn-findings .fd-row{padding:12px 16px;border-bottom:1px solid #21262d;cursor:pointer;border-left:3px solid transparent;}
  #pwn-findings .fd-row:hover{background:#1c2128;}
  #pwn-findings .fd-row.active{background:#1c2128;border-left-color:var(--accent);}
  #pwn-findings .fd-chain{font-size:12px;font-family:ui-monospace,monospace;color:#c9d1d9;margin-top:6px;word-break:break-word;}
  #pwn-findings .fd-empty{padding:16px;color:var(--muted);font-size:13px;}
  #pwn-legend{
    position:fixed;bottom:16px;left:16px;background:rgba(22,27,34,0.92);border:1px solid var(--border);
    border-radius:8px;padding:12px 14px;font-size:11px;z-index:9998;color:var(--text);
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
  }
  #pwn-legend h4{margin:0 0 8px;font-size:12px;color:var(--blue);}
  #pwn-legend .row{display:flex;align-items:center;margin:3px 0;}
  #pwn-legend .swatch{width:11px;height:11px;border-radius:50%;margin-right:8px;}
  #pwn-legend .edge-swatch{width:18px;height:3px;margin-right:8px;}
  #pwn-legend hr{border:none;border-top:1px solid var(--border);margin:7px 0;}
  #pwn-toast{
    position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(20px);
    background:var(--panel);border:1px solid var(--border);border-left:3px solid var(--accent);
    color:var(--text);padding:12px 18px;border-radius:8px;font-size:13px;z-index:10001;opacity:0;
    transition:all .25s ease;max-width:520px;box-shadow:0 8px 30px rgba(0,0,0,.4);
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
  }
  #pwn-toast.show{opacity:1;transform:translateX(-50%) translateY(0);}
</style>

<div id="pwn-topbar">
  <div class="brand">Pwn<span>Graph</span></div>
  <input id="pwn-search" placeholder="Search nodes (tool, type)…" oninput="PWN.search(this.value)">
  <button class="pwn-btn" id="pwn-workflow-btn" onclick="PWN.workflow()">Workflow</button>
  <button class="pwn-btn" id="pwn-findings-btn" onclick="PWN.toggleFindings()">Findings</button>
  <button class="pwn-btn" id="pwn-attack-toggle" onclick="PWN.toggleAttackOnly()">Attack paths only</button>
  <button class="pwn-btn" onclick="PWN.criticalOnly()">Critical only</button>
  <button class="pwn-btn" onclick="PWN.chokePoint()">Find choke point</button>
  <div class="pwn-spacer"></div>
  <button class="pwn-btn" onclick="PWN.reset()">Reset view</button>
  <button class="pwn-btn" style="background:var(--accent);border-color:var(--accent);color:#fff;font-weight:600;" onclick="window.open('report.html','_blank')">&#x2197; Open Report</button>
</div>

<div id="pwn-findings">
  <div class="fd-head">
    <span>Findings (<span id="fd-count">0</span>)</span>
    <span class="sb-close" onclick="PWN.toggleFindings()">&times;</span>
  </div>
  <div class="fd-list" id="fd-list"></div>
</div>

<div id="pwn-sidebar">
  <div class="sb-head">
    <span class="sb-close" onclick="PWN.closeSidebar()">&times;</span>
    <div class="sb-type" id="sb-type"></div>
    <div class="sb-title" id="sb-title"></div>
  </div>
  <div class="sb-body" id="sb-body"></div>
</div>

<div id="pwn-legend">
  <h4>Legend</h4>
  <div class="row"><span class="swatch" style="background:#E74C3C"></span>User Input</div>
  <div class="row"><span class="swatch" style="background:#3498DB"></span>Tool Call</div>
  <div class="row"><span class="swatch" style="background:#F1C40F"></span>Tool Result</div>
  <div class="row"><span class="swatch" style="background:#95A5A6"></span>LLM Thought</div>
  <div class="row"><span class="swatch" style="background:#2ECC71"></span>Final Answer</div>
  <div class="row"><span class="swatch" style="background:#FF2E63"></span>Dangerous Outcome</div>
  <hr/>
  <div class="row"><span class="edge-swatch" style="background:#E74C3C"></span>Direct Injection</div>
  <div class="row"><span class="edge-swatch" style="background:#9B59B6"></span>Context Poisoning</div>
  <div class="row"><span class="edge-swatch" style="background:#E67E22"></span>Tool Manipulation</div>
  <div class="row"><span class="edge-swatch" style="background:#C0392B"></span>Data Exfil</div>
</div>

<div id="pwn-toast"></div>

<script type="text/javascript">
(function(){
  var NODE_COLORS={user_input:'#E74C3C',tool_call:'#3498DB',tool_result:'#F1C40F',agent_thought:'#95A5A6',final_answer:'#2ECC71',dangerous:'#FF2E63'};
  var TYPE_LABEL={user_input:'User Input',tool_call:'Tool Call',tool_result:'Tool Result',agent_thought:'LLM Thought',final_answer:'Final Answer',dangerous:'Dangerous Outcome'};
  var SEV_COLOR={critical:'#C0392B',high:'#E67E22',medium:'#D4AC0D',low:'#1E8449'};
  var DIM_NODE={color:{background:'#161b22',border:'#21262d'},font:{color:'#30363d',size:22,strokeWidth:4,strokeColor:'#0D1117'}};
  var DIM_EDGE='#1b2027';

  var net,nodes,edges;
  var baseColor={},baseBorder={},baseEdge={};
  var outAdj={},inAdj={};
  var attackOnly=false,curId=null,toastT=null;

  function poll(){ if(window.network&&window.nodes&&window.edges){init();} else {setTimeout(poll,60);} }
  poll();

  function init(){
    net=window.network; nodes=window.nodes; edges=window.edges;

    // Large traces (hundreds of nodes) can make vis's loading bar loop forever.
    // Cap stabilization so the loader completes fast, but keep physics ON with a
    // minVelocity cutoff: the graph settles by itself yet still moves when you
    // drag a node (interactive, not frozen).
    function hideLoader(){ var lb=document.getElementById('loadingBar'); if(lb) lb.style.display='none'; }
    try{
      net.setOptions({physics:{stabilization:{enabled:true,iterations:200,updateInterval:25,fit:true},minVelocity:0.75}});
      net.once('stabilizationIterationsDone', hideLoader);
      // Safety: hide the loader after 6s even if stabilization never signals done.
      setTimeout(hideLoader, 6000);
    }catch(e){}

    nodes.get().forEach(function(n){ baseColor[n.id]=n.color; baseBorder[n.id]=(n.borderWidth||1); });
    edges.get().forEach(function(e){
      baseEdge[e.id]=e.color;
      (outAdj[e.from]=outAdj[e.from]||[]).push(e.to);
      (inAdj[e.to]=inAdj[e.to]||[]).push(e.from);
    });
    net.on('click',function(p){
      if(p.nodes&&p.nodes.length){ var id=p.nodes[0]; showSidebar(nodes.get(id)); trace(id); }
      else { closeSidebar(); restoreColors(); }   // clear highlight, keep zoom
    });
    net.on('doubleClick',function(p){
      if(!(p.nodes&&p.nodes.length)){ reset(); }   // double-click empty = full reset + refit
    });
    buildFindings();
  }

  // --- Findings panel: list discovered paths, highlight one on click --------
  function buildFindings(){
    var data=window.PWN_FINDINGS||[];
    var btn=document.getElementById('pwn-findings-btn');
    if(btn) btn.textContent='Findings ('+data.length+')';
    var cnt=document.getElementById('fd-count'); if(cnt) cnt.textContent=data.length;
    var list=document.getElementById('fd-list'); if(!list) return;
    if(!data.length){ list.innerHTML='<div class="fd-empty">No dangerous paths found.</div>'; return; }
    var html='';
    data.forEach(function(f){
      var col=SEV_COLOR[f.severity]||'#888';
      html+='<div class="fd-row" data-i="'+f.i+'" onclick="PWN.selectFinding('+f.i+')">'
          + '<span class="sb-badge" style="background:'+col+';color:#fff">'+f.severity+'</span>'
          + (f.confidence==='low'?' <span style="font-size:10px;color:var(--muted)">· verify</span>':'')
          + '<div class="fd-chain">'+esc(f.label)+' &rarr; <span style="color:#FF2E63">DANGER</span></div>'
          + '</div>';
    });
    list.innerHTML=html;
  }
  function toggleFindings(){ document.getElementById('pwn-findings').classList.toggle('open'); }
  function selectFinding(i){
    var f=(window.PWN_FINDINGS||[])[i]; if(!f) return;
    document.querySelectorAll('#pwn-findings .fd-row').forEach(function(r){
      r.classList.toggle('active', r.dataset.i===(''+i));
    });
    closeSidebar();
    highlightPath(f.nodes);
  }
  function highlightPath(ids){
    nodes.update(ids.map(function(id){return {id:id,hidden:false};}));  // path always visible
    edges.update(edges.get().filter(function(e){return idIn(ids,e.from)&&idIn(ids,e.to);}).map(function(e){return {id:e.id,hidden:false};}));
    dimEverything(); brightNodes(ids);
    var set={}; ids.forEach(function(x){set[x]=1;}); brightEdgesWithin(set);
    if(ids.length){ nodes.update({id:ids[ids.length-1],borderWidth:6}); net.fit({nodes:ids,animation:true}); }
  }
  function idIn(arr,v){ return arr.indexOf(v)>=0; }

  // BFS over an adjacency map; returns reachable node ids (excludes start).
  function walk(start,adj){
    var seen={},q=[start];
    while(q.length){ var c=q.pop(); (adj[c]||[]).forEach(function(n){ if(!seen[n]){seen[n]=1;q.push(n);} }); }
    return Object.keys(seen);
  }

  function dimEverything(){
    nodes.update(nodes.get().map(function(n){return Object.assign({id:n.id},DIM_NODE);}));
    edges.update(edges.get().map(function(e){return {id:e.id,color:DIM_EDGE};}));
  }
  function brightNodes(ids){
    nodes.update(ids.map(function(id){return {id:id,color:baseColor[id],borderWidth:baseBorder[id],font:{color:'#E6EDF3',size:22,strokeWidth:4,strokeColor:'#0D1117'}};}));
  }
  function brightEdgesWithin(set){
    edges.update(edges.get().filter(function(e){return set[e.from]&&set[e.to];}).map(function(e){return {id:e.id,color:baseEdge[e.id]};}));
  }

  function trace(id){
    var set={}; set[id]=1;
    walk(id,inAdj).forEach(function(x){set[x]=1;});
    walk(id,outAdj).forEach(function(x){set[x]=1;});
    dimEverything(); brightNodes(Object.keys(set)); brightEdgesWithin(set);
    nodes.update({id:id,borderWidth:5});
  }
  function traceCur(){ if(curId)trace(curId); }

  // Un-dim everything (restore node/edge colours) WITHOUT moving the camera.
  // Used on a stray single click so the view doesn't jump.
  function restoreColors(){
    nodes.update(nodes.get().map(function(n){return {id:n.id,color:baseColor[n.id],borderWidth:baseBorder[n.id],font:{color:'#E6EDF3',size:22,strokeWidth:4,strokeColor:'#0D1117'}};}));
    edges.update(edges.get().map(function(e){return {id:e.id,color:baseEdge[e.id]};}));
  }

  // Full reset: restore colours, un-hide any filtered nodes, and refit camera.
  function reset(){
    clearWorkflow();
    wfActive=false; var wb=document.getElementById('pwn-workflow-btn'); if(wb)wb.classList.remove('active');
    var lg=document.getElementById('pwn-legend'); if(lg)lg.style.display='';
    restoreColors();
    nodes.update(nodes.get().map(function(n){return {id:n.id,hidden:false};}));
    edges.update(edges.get().map(function(e){return {id:e.id,hidden:false};}));
    attackOnly=false; var b=document.getElementById('pwn-attack-toggle'); if(b)b.classList.remove('active');
    if(net)net.fit({animation:true});
  }

  // --- Workflow view: a clean "how the agent is wired" diagram ---------------
  // Hides the whole trace graph and draws a simple synthetic overview:
  //   User → AI Agent ⇄ (each tool it can call) → Answer
  // Nothing adversarial, nothing about findings — just the agent's structure.
  var wfNodes=[],wfEdges=[],wfActive=false;
  function workflow(){
    wfActive=!wfActive;
    var b=document.getElementById('pwn-workflow-btn');
    if(!wfActive){ if(b)b.classList.remove('active'); reset(); return; }
    if(b)b.classList.add('active');
    closeSidebar();
    var fp=document.getElementById('pwn-findings'); if(fp)fp.classList.remove('open');
    var lg=document.getElementById('pwn-legend'); if(lg)lg.style.display='none';
    showWorkflow();
  }
  function showWorkflow(){
    clearWorkflow();
    // Hide the real trace graph entirely.
    nodes.update(nodes.get().map(function(n){return {id:n.id,hidden:true};}));
    edges.update(edges.get().map(function(e){return {id:e.id,hidden:true};}));
    // Collect the unique tools the agent actually called.
    var seen={}, tools=[];
    nodes.get().forEach(function(n){
      if(n.node_type==='tool_call'&&n.pwn_name&&!seen[n.pwn_name]){ seen[n.pwn_name]=1; tools.push(n.pwn_name); }
    });
    var elabel={color:'#8b949e',size:11,strokeWidth:0,background:'rgba(13,17,23,0.7)'};
    var N=[
      {id:'__wf_user',  label:'User',     shape:'dot', size:24, color:'#E74C3C', font:{color:'#E6EDF3',size:15}},
      {id:'__wf_agent', label:'AI Agent', shape:'box', color:{background:'#58a6ff',border:'#1f6feb'}, font:{color:'#0D1117',size:18}},
      {id:'__wf_answer',label:'Answer',   shape:'dot', size:24, color:'#2ECC71', font:{color:'#E6EDF3',size:15}}
    ];
    var E=[
      {id:'__wfe_ua', from:'__wf_user', to:'__wf_agent',  arrows:'to', label:'request',  color:'#8b949e', font:elabel},
      {id:'__wfe_aa', from:'__wf_agent',to:'__wf_answer', arrows:'to', label:'response', color:'#8b949e', font:elabel}
    ];
    tools.forEach(function(t,i){
      N.push({id:'__wf_t_'+i, label:t, shape:'box', color:{background:'#3498DB',border:'#2c6da3'}, font:{color:'#fff',size:13}});
      E.push({id:'__wfe_t_'+i, from:'__wf_agent', to:'__wf_t_'+i, arrows:'to;from', dashes:true, color:'#3498DB', label:'uses', font:elabel});
    });
    wfNodes=N.map(function(n){return n.id;});
    wfEdges=E.map(function(e){return e.id;});
    nodes.add(N); edges.add(E);
    setTimeout(function(){ if(net) net.fit({animation:true}); }, 200);
  }
  function clearWorkflow(){
    try{ if(wfEdges.length) edges.remove(wfEdges); }catch(e){}
    try{ if(wfNodes.length) nodes.remove(wfNodes); }catch(e){}
    wfNodes=[]; wfEdges=[];
  }

  function toggleAttackOnly(){
    attackOnly=!attackOnly;
    var b=document.getElementById('pwn-attack-toggle');
    if(!attackOnly){ reset(); return; }
    b.classList.add('active');
    var keep={};
    edges.get().forEach(function(e){ if(e.is_adversarial){ keep[e.from]=1; keep[e.to]=1; } });
    nodes.get().forEach(function(n){ if(n.is_adversarial) keep[n.id]=1; });
    nodes.update(nodes.get().map(function(n){return {id:n.id,hidden:!keep[n.id]};}));
    edges.update(edges.get().map(function(e){return {id:e.id,hidden:!e.is_adversarial};}));
    net.fit({animation:true});
  }

  function criticalOnly(){
    var sinks=nodes.get().filter(function(n){return n.node_type==='dangerous'&&n.severity==='critical';});
    if(!sinks.length){ toast('No critical paths found in this graph.'); return; }
    var set={};
    sinks.forEach(function(s){ set[s.id]=1; walk(s.id,inAdj).forEach(function(x){set[x]=1;}); });
    nodes.update(nodes.get().map(function(n){return {id:n.id,hidden:!set[n.id]};}));
    edges.update(edges.get().map(function(e){return {id:e.id,hidden:!(set[e.from]&&set[e.to])};}));
    var b=document.getElementById('pwn-attack-toggle'); if(b)b.classList.remove('active'); attackOnly=false;
    net.fit({animation:true});
    toast(sinks.length+' critical path'+(sinks.length>1?'s':'')+' shown. Reset to see the full graph.');
  }

  function chokePoint(){
    var sinks=nodes.get().filter(function(n){return n.node_type==='dangerous';});
    if(!sinks.length){ toast('No dangerous paths to analyse.'); return; }
    var counts={};
    sinks.forEach(function(s){
      var names={};
      walk(s.id,inAdj).forEach(function(aid){ var n=nodes.get(aid); if(n&&n.node_type==='tool_call'&&n.pwn_name) names[n.pwn_name]=1; });
      Object.keys(names).forEach(function(nm){counts[nm]=(counts[nm]||0)+1;});
    });
    var best=null,bestN=0;
    Object.keys(counts).forEach(function(nm){ if(counts[nm]>bestN){bestN=counts[nm];best=nm;} });
    if(!best){ toast('No tool sits on a dangerous path.'); return; }
    var hits=nodes.get().filter(function(n){return n.node_type==='tool_call'&&n.pwn_name===best;}).map(function(n){return n.id;});
    dimEverything();
    nodes.update(hits.map(function(id){return {id:id,color:{background:'#F1C40F',border:'#FFD93B'},borderWidth:6,font:{color:'#E6EDF3',size:22,strokeWidth:4,strokeColor:'#0D1117'}};}));
    toast('Choke point: '+best+' — sits on '+bestN+' of '+sinks.length+' attack path'+(sinks.length>1?'s':'')+'. Constrain it to break the most chains.');
  }

  function search(q){
    q=(q||'').trim().toLowerCase();
    if(!q){ reset(); return; }
    var hit=nodes.get().filter(function(n){
      return (''+(n.label||'')).toLowerCase().indexOf(q)>=0
          || (''+(n.pwn_name||'')).toLowerCase().indexOf(q)>=0
          || (''+(n.node_type||'')).toLowerCase().indexOf(q)>=0;
    });
    dimEverything();
    var ids=hit.map(function(n){return n.id;});
    nodes.update(ids.map(function(id){return {id:id,color:baseColor[id],borderWidth:5,font:{color:'#E6EDF3',size:22,strokeWidth:4,strokeColor:'#0D1117'}};}));
    var set={}; ids.forEach(function(i){set[i]=1;}); brightEdgesWithin(set);
  }

  function esc(s){ return (''+(s==null?'':s)).replace(/[&<>]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;'}[c];}); }

  function showSidebar(n){
    if(!n) return;
    curId=n.id;
    document.getElementById('sb-type').textContent=TYPE_LABEL[n.node_type]||n.node_type||'Node';
    document.getElementById('sb-title').textContent=n.pwn_name||n.label||n.id;
    var rows='';
    function kv(k,v){ rows+='<div class="kv"><span class="k">'+k+'</span><span class="v">'+v+'</span></div>'; }
    var sw='<span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:'+(NODE_COLORS[n.node_type]||'#888')+';margin-right:6px"></span>';
    kv('Type', sw+esc(TYPE_LABEL[n.node_type]||n.node_type));
    kv('Adversarial', n.is_adversarial?'<span class="sb-badge" style="background:#C0392B;color:#fff">yes</span>':'<span class="sb-badge" style="background:#30363d;color:#8b949e">no</span>');
    if(n.severity) kv('Severity','<span class="sb-badge" style="background:'+(SEV_COLOR[n.severity]||'#888')+';color:#fff">'+esc(n.severity)+'</span>');
    if(n.confidence) kv('Confidence', esc(n.confidence));
    if(n.payload_id) kv('Payload ID','<code>'+esc(n.payload_id)+'</code>');
    var body='<div>'+rows+'</div>';
    if(n.pwn_content){ body+='<div style="margin-top:14px"><div class="sb-type">Content</div><pre>'+esc(n.pwn_content)+'</pre></div>'; }
    body+='<div style="margin-top:16px;display:flex;gap:8px">'
       +'<button class="pwn-btn" onclick="PWN.traceCur()">Trace attack path</button>'
       +'<button class="pwn-btn" onclick="PWN.copyCur()">Copy node id</button></div>';
    document.getElementById('sb-body').innerHTML=body;
    document.getElementById('pwn-sidebar').classList.add('open');
  }
  function closeSidebar(){ document.getElementById('pwn-sidebar').classList.remove('open'); }

  function toast(msg){
    var t=document.getElementById('pwn-toast'); t.textContent=msg; t.classList.add('show');
    clearTimeout(toastT); toastT=setTimeout(function(){t.classList.remove('show');},6000);
  }
  function copyCur(){ if(curId&&navigator.clipboard){ navigator.clipboard.writeText(curId); toast('Copied: '+curId); } }

  window.PWN={reset:reset,toggleAttackOnly:toggleAttackOnly,criticalOnly:criticalOnly,
              chokePoint:chokePoint,search:search,trace:trace,traceCur:traceCur,
              closeSidebar:closeSidebar,copyCur:copyCur,
              toggleFindings:toggleFindings,selectFinding:selectFinding,
              workflow:workflow};
})();
</script>
'''

log = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).parent / "templates"


class Reporter:
    """Renders artifacts from a built graph."""

    def __init__(self) -> None:
        self._jinja = Environment(
            loader=FileSystemLoader(str(_TEMPLATES_DIR)),
            autoescape=select_autoescape(["html"]),
        )

    # ------------------------------------------------------------------
    # Interactive graph (pyvis)
    # ------------------------------------------------------------------

    def render_graph(
        self,
        graph: nx.MultiDiGraph,
        output_path: Path,
        paths: list[AttackPath] | None = None,
    ) -> Path:
        """Render the attack graph as an interactive HTML file via pyvis."""
        try:
            from pyvis.network import Network
        except ImportError as exc:  # pragma: no cover
            raise ImportError("pyvis is required: pip install pyvis") from exc

        net = Network(
            height="100vh",
            width="100%",
            bgcolor="#0D1117",
            font_color="#E6EDF3",
            directed=True,
            cdn_resources="remote",
            notebook=False,
        )
        net.barnes_hut(
            gravity=-12000,
            central_gravity=0.3,
            spring_length=140,
            spring_strength=0.05,
            damping=0.09,
        )

        for node_id, attrs in graph.nodes(data=True):
            ntype = attrs.get("node_type", "")
            color = attrs.get("color", "#3498DB")
            is_adv = bool(attrs.get("is_adversarial", False))
            # The near-black sink colour is invisible on the dark canvas — make
            # the most important node the brightest one on screen.
            if ntype == NodeType.DANGEROUS_OUTCOME.value:
                color = "#FF2E63"
            net.add_node(
                node_id,
                label=attrs.get("label", node_id[:8]),
                title=attrs.get("title", ""),
                color=color,
                shape=attrs.get("shape", "dot"),
                borderWidth=3 if is_adv else 1,
                # Larger label with a dark text-outline so it stays legible over
                # any node colour (incl. the bright yellow tool_result nodes).
                font={"color": "#E6EDF3", "size": 22, "strokeWidth": 4,
                      "strokeColor": "#0D1117"},
                # Custom metadata consumed by the injected UI. vis.js preserves
                # unknown keys on the DataSet, so the client can read them back.
                node_type=ntype,
                is_adversarial=is_adv,
                pwn_name=attrs.get("name", ""),
                pwn_content=attrs.get("content", ""),
                payload_id=attrs.get("payload_id") or "",
                severity=attrs.get("outcome_severity") or "",
                confidence=attrs.get("confidence") or "",
            )

        for u, v, attrs in graph.edges(data=True):
            is_adv = bool(attrs.get("is_adversarial", False))
            net.add_edge(
                u, v,
                color=attrs.get("color", "#BDC3C7"),
                title=attrs.get("title", ""),
                label=attrs.get("label", ""),
                width=3 if is_adv else 1,
                dashes=bool(attrs.get("dashes", False)),
                arrows="to",
                font={"color": "#8b949e", "size": 9, "strokeWidth": 0,
                      "background": "rgba(13,17,23,0.7)"},
                edge_type=attrs.get("edge_type", ""),
                is_adversarial=is_adv,
            )

        # pyvis 0.3+: use save_graph (it writes the html itself); fall back to
        # write_html(notebook=False) on older versions.
        try:
            net.save_graph(str(output_path))
        except Exception:  # noqa: BLE001
            net.write_html(str(output_path), open_browser=False, notebook=False)

        # Inject the BloodHound-style control surface (top bar, sidebar,
        # path tracing, queries, search, legend, findings panel) over pyvis's
        # bare canvas.
        self._inject_ui(output_path, paths or [])
        log.info("Graph rendered to %s", output_path)
        return output_path

    # ------------------------------------------------------------------
    # HTML report
    # ------------------------------------------------------------------

    def render_report(
        self,
        paths: list[AttackPath],
        findings: list[Finding],
        output_path: Path,
        target_name: str,
        tool_inventory: list[str],
        asr: dict | None = None,
        owasp_coverage: list[dict] | None = None,
    ) -> Path:
        """Render a severity-ranked HTML summary with remediation hints.

        ``asr`` is the optional Attack Success Rate rollup from
        ``pwngraph.oracle.aggregate_asr`` (overall + per attack class). When
        present, the report leads with the reliability story (ASR + 95% CI)
        rather than just raw path counts.

        ``owasp_coverage`` is the OWASP LLM Top-10 (2025) coverage matrix from
        ``PwnGraph.owasp_coverage()`` — rendered as an honest, scope-aware table.
        """
        tpl = self._jinja.get_template("report.html.j2")
        asr = asr or {}
        html = tpl.render(
            target_name=target_name,
            tool_inventory=tool_inventory,
            paths=paths,
            findings=findings,
            severity_counts=_severity_counts(paths),
            attack_class_counts=_attack_class_counts(paths),
            edge_type_counts=_edge_type_counts(paths),
            remediation=_remediation_for(paths),
            tool_risk=_tool_risk(paths),
            path_extras=_path_extras(paths),
            asr_overall=asr.get("overall", {}),
            asr_by_class=asr.get("by_class", {}),
            owasp_coverage=owasp_coverage or [],
        )
        output_path.write_text(html, encoding="utf-8")
        log.info("Report rendered to %s", output_path)
        return output_path

    # ------------------------------------------------------------------
    # Trace dump
    # ------------------------------------------------------------------

    def dump_trace(self, events: list[TraceEvent], output_path: Path) -> Path:
        """Write the full event stream to JSON for offline analysis."""
        output_path.write_text(
            json.dumps(
                [e.model_dump(mode="json") for e in events],
                indent=2,
                default=str,
            ),
            encoding="utf-8",
        )
        return output_path

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _inject_ui(self, path: Path, paths: list[AttackPath]) -> None:
        """Inject the BloodHound-style control surface over the bare pyvis canvas.

        Adds, all client-side (no extra deps): a dark theme, a top command bar
        with live node search, an "attack paths only" toggle, "critical only"
        and "find choke point" queries, a slide-in node inspector sidebar,
        click-to-trace path highlighting, and a Findings panel that lists every
        discovered path (severity-ranked) and highlights its exact chain on
        click. Reads the custom metadata ``render_graph`` stamped on each node.
        """
        try:
            html = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return

        findings_js = "<script>window.PWN_FINDINGS=" + json.dumps(
            _findings_payload(paths)
        ) + ";</script>\n"
        block = findings_js + _GRAPH_UI

        if "</body>" in html:
            html = html.replace("</body>", block + "</body>")
        else:
            html += block
        path.write_text(html, encoding="utf-8")


# ---------------------------------------------------------------------------
# Helpers — aggregations used by the template
# ---------------------------------------------------------------------------

def _severity_counts(paths: list[AttackPath]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for p in paths:
        counts[p.severity.value] = counts.get(p.severity.value, 0) + 1
    return counts


def _attack_class_counts(paths: list[AttackPath]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for p in paths:
        for ev in p.events:
            pid = ev.payload_id
            if not pid:
                continue
            key = ev.metadata.get("attack_class", "unknown")
            counts[key] = counts.get(key, 0) + 1
            break
    return counts


def _edge_type_counts(paths: list[AttackPath]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for p in paths:
        for e in p.edge_types:
            counts[e.value] = counts.get(e.value, 0) + 1
    return counts


def _tool_risk(paths: list[AttackPath]) -> list[tuple[str, int]]:
    """Count how many distinct dangerous paths each tool appears in."""
    counts: dict[str, int] = {}
    for p in paths:
        seen: set[str] = set()
        for ev in p.events:
            if ev.node_type is NodeType.TOOL_CALL and ev.name not in seen:
                counts[ev.name] = counts.get(ev.name, 0) + 1
                seen.add(ev.name)
    return sorted(counts.items(), key=lambda x: -x[1])


def _path_extras(paths: list[AttackPath]) -> dict[str, dict]:
    """Per-path derived data: delivery_input, canary token, attack_class."""
    out: dict[str, dict] = {}
    for p in paths:
        delivery = ""
        canary = ""
        attack_class = "unknown"
        for ev in p.events:
            if not ev.is_adversarial:
                continue
            ac = ev.metadata.get("attack_class")
            if ac and attack_class == "unknown":
                attack_class = ac
            if ev.node_type is NodeType.USER_INPUT and not delivery:
                delivery = ev.content
            if not canary:
                m = _CANARY_RE.search(ev.content)
                if m:
                    canary = m.group()
        out[p.path_id] = {
            "delivery_input": delivery,
            "canary": canary,
            "attack_class": attack_class,
        }
    return out


def _findings_payload(paths: list[AttackPath]) -> list[dict]:
    """Serialise each path for the graph's Findings panel.

    Each entry carries the ordered vis node ids that make up the chain (so the
    client can highlight exactly that path), plus the severity/confidence and a
    readable tool-chain label. Severity-ranked to match the report.
    """
    out: list[dict] = []
    for i, p in enumerate(sorted(paths, key=lambda x: -x.severity.score)):
        tool_chain = [e.name for e in p.events if e.node_type is NodeType.TOOL_CALL]
        label = " → ".join(tool_chain) if tool_chain else (
            p.events[-1].name if p.events else "path"
        )
        out.append({
            "i": i,
            "severity": p.severity.value,
            "confidence": p.confidence,
            "label": label,
            "nodes": [e.event_id for e in p.events],
        })
    return out


def _remediation_for(paths: list[AttackPath]) -> list[dict[str, str]]:
    """Return remediation cards keyed by which edge types appear."""
    edges_seen = {e.value for p in paths for e in p.edge_types}
    out: list[dict[str, str]] = []

    if EdgeType.DIRECT_INJECTION.value in edges_seen:
        out.append({
            "title": "Direct prompt injection",
            "body": (
                "Treat user input as untrusted in the system prompt. Use a "
                "structured input boundary (e.g. dedicated tool 'user_says') "
                "and instruct the LLM never to execute instructions inside "
                "user-supplied text."
            ),
        })
    if EdgeType.CONTEXT_POISONING.value in edges_seen:
        out.append({
            "title": "Context poisoning via tools",
            "body": (
                "Apply provenance tagging to retrieved content. Constrain "
                "the LLM to treat tool output as data, not instructions — "
                "wrap retrieved text in clearly-delimited blocks and prompt "
                "the model that instructions inside those blocks must be "
                "ignored."
            ),
        })
    if EdgeType.TOOL_MANIPULATION.value in edges_seen:
        out.append({
            "title": "Tool argument manipulation",
            "body": (
                "Validate tool arguments against an allow-list before "
                "execution. For high-impact tools (email, code execution, "
                "purchases), require a second confirmation pass that "
                "re-summarises the action in the user's own words."
            ),
        })
    if EdgeType.DATA_EXFIL.value in edges_seen:
        out.append({
            "title": "Data exfiltration",
            "body": (
                "Block outbound HTTP from tools by default; allow-list "
                "domains. Strip URLs and email addresses from any LLM-"
                "controlled tool argument. Audit-log every tool call with "
                "external destinations."
            ),
        })
    return out
