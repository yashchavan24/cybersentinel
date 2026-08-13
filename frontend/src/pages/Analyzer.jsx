import React, { useState } from 'react';
import { api } from '../api.js';
import { Card, Badge, Spinner, SEV_COLORS } from '../components.jsx';
const SAMPLES = {
  'Phishing email':`From: billing@micr0soft-secure.tk\nSubject: URGENT: Your account will be suspended in 24 hours\n\nDear customer, we detected unusual activity on your account.\nClick here to verify your password immediately: http://login-micr0soft-verify.tk/account\nFailure to confirm will result in permanent deactivation.`,
  'SQLi log':`203.0.113.42 - - "GET /products?id=41' OR '1'='1 HTTP/1.1" 200\n203.0.113.42 - - "GET /products?id=41 UNION SELECT username, password FROM users-- HTTP/1.1" 200\nUser-Agent: sqlmap/1.8.2`,
  'EDR alert':`EDR ALERT [WIN-DC01]: process svch0st.exe (PID 5521) spawned from winword.exe macro\nSHA256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\nNetwork: beaconing to update-cdn-metrics.ru every 30 seconds (C2 callback suspected)`
};
export default function Analyzer() {
  const [content,setContent]=useState(''); const [type,setType]=useState('log');
  const [a,setA]=useState(null); const [busy,setBusy]=useState(false); const [err,setErr]=useState(''); const [copied,setCopied]=useState(false);
  const run=async()=>{if(!content.trim())return;setBusy(true);setErr('');setA(null);try{setA((await api('/analyze',{method:'POST',body:{content,type}})).analysis);}catch(e){setErr(e.message);}finally{setBusy(false);}};
  const copy=()=>{const md=[`# CyberSentinel Analysis`,`Severity: ${a.severity} (${a.score}/100)`,`Verdict: ${a.verdict}`,'','## Detections',...a.detections.map(d=>`- ${d.name} [${d.mitre}] +${d.weight}`),'','## IOCs',...Object.entries(a.iocs).flatMap(([k,v])=>v.length?[`- ${k}: ${v.map(x=>x.value||x).join(', ')}`]:[]),'','## Actions',...a.recommendations.map(x=>`- ${x}`)].join('\n');navigator.clipboard.writeText(md);setCopied(true);setTimeout(()=>setCopied(false),2000);};
  const color=a?SEV_COLORS[a.severity]:'';
  return (<div className="page"><h1>⚡ AI Threat Analyzer</h1><p className="muted">Paste telemetry — hybrid engine classifies, extracts IOCs, recommends response.</p>
    <div className="samples">{Object.keys(SAMPLES).map(k=><button key={k} className="btn ghost sm" onClick={()=>setContent(SAMPLES[k])}>Try: {k}</button>)}</div>
    <div className="analyzer-grid">
      <Card title="Input Telemetry"><div className="row"><select className="input sm" value={type} onChange={e=>setType(e.target.value)}>{['log','alert','email','ioc','incident'].map(t=><option key={t}>{t}</option>)}</select><button className="btn primary" onClick={run} disabled={busy}>{busy?'Analyzing…':'Run AI Analysis'}</button></div><textarea className="input mono" rows="14" placeholder="Paste raw log lines, email body, EDR alert…" value={content} onChange={e=>setContent(e.target.value)}/>{err&&<div className="flash err">{err}</div>}</Card>
      <div>{busy&&<Spinner/>}{a&&!busy&&(<div className="result-stack">
        <div className="verdict-card" style={{borderColor:color+'55'}}><div className="score-big" style={{color}}>{a.score}</div><div><Badge color={color}>{a.severity}</Badge><div className="verdict-txt">{a.verdict}</div><div className="muted mono">{a.engine}</div></div><button className="btn ghost sm" onClick={copy}>{copied?'✓ Copied':'📋 Report'}</button></div>
        {a.detections.length>0&&<Card title={`Detections (${a.detections.length})`}>{a.detections.map((d,i)=><div key={i} className="list-row wrap"><span className="list-title">{d.name}</span><Badge color="var(--purple)">{d.mitre}</Badge><span className="muted mono">+{d.weight}</span>{d.detail&&<div className="muted mono small w100">{d.detail}</div>}</div>)}</Card>}
        <Card title="Extracted IOCs">{Object.entries(a.iocs).every(([,v])=>!v.length)&&<div className="muted">No IOCs found</div>}{Object.entries(a.iocs).map(([k,v])=>v.length>0&&<div key={k} className="chip-row"><b className="mono">{k}:</b>{v.map((x,i)=><span key={i} className="chip mono">{x.value||x}{x.internal?' (internal)':''}</span>)}</div>)}</Card>
        <Card title="Recommended Actions"><ol className="rec-list">{a.recommendations.map((r,i)=><li key={i}>{r}</li>)}</ol></Card>
        {a.llm_narrative&&<Card title="✨ LLM Analyst Narrative"><p className="mono small">{a.llm_narrative}</p></Card>}
      </div>)}</div>
    </div>
  </div>);
}
