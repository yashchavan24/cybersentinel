import React, { useCallback, useEffect, useState } from 'react';
import { api } from '../api.js';
import { Card, Spinner, SevBadge, Badge, Msg, fmt } from '../components.jsx';
const STATUSES = ['new','triaged','investigating','mitigated','closed'];
function NewEntry({onDone,flash}) {
  const [f,setF]=useState({title:'',type:'log',source:'',content:''}); const [busy,setBusy]=useState(false);
  const set=k=>e=>setF({...f,[k]:e.target.value});
  const submit=async e=>{e.preventDefault();setBusy(true);try{const d=await api('/entries',{method:'POST',body:{...f,auto_analyze:true}});onDone(d.entry);flash(d.analysis?`Saved & analyzed → ${d.analysis.severity}`:'Saved');}catch(ex){flash('⚠ '+ex.message);}finally{setBusy(false);}};
  return (<Card title="New Entry"><form onSubmit={submit} className="form-grid"><input className="input" placeholder="Title" value={f.title} onChange={set('title')} required/><div className="row"><select className="input" value={f.type} onChange={set('type')}>{['log','alert','email','ioc','incident'].map(t=><option key={t}>{t}</option>)}</select><input className="input" placeholder="Source" value={f.source} onChange={set('source')}/></div><textarea className="input mono" rows="6" placeholder="Raw telemetry…" value={f.content} onChange={set('content')} required/><button className="btn primary" disabled={busy}>{busy?'Saving…':'💾 Save + Auto-analyze'}</button></form></Card>);
}
export default function Entries() {
  const [rows,setRows]=useState(null); const [sev,setSev]=useState(''); const [q,setQ]=useState('');
  const [open,setOpen]=useState(null); const [showForm,setShowForm]=useState(false);
  const [msg,setMsg]=useState(''); const [busy,setBusy]=useState(null);
  const flash=m=>{setMsg(m);setTimeout(()=>setMsg(''),4000);};
  const load=useCallback(()=>{const p=new URLSearchParams();if(sev)p.set('severity',sev);if(q)p.set('q',q);api('/entries?'+p).then(d=>setRows(d.entries)).catch(e=>flash('⚠ '+e.message));},[sev,q]);
  useEffect(()=>{load();},[load]);
  const doAnalyze=async id=>{setBusy(id);try{const d=await api(`/entries/${id}/analyze`,{method:'POST'});setRows(rs=>rs.map(r=>r.id===id?d.entry:r));flash(d.dispatched.length?`✅ Dispatched to ${d.dispatched.length} receiver(s)`:'✅ Analyzed');}catch(e){flash('⚠ '+e.message);}finally{setBusy(null);}};
  const setStatus=async(id,status)=>{try{const d=await api(`/entries/${id}`,{method:'PATCH',body:{status}});setRows(rs=>rs.map(r=>r.id===id?d.entry:r));}catch(e){flash('⚠ '+e.message);}};
  const del=async id=>{if(!confirm('Delete?'))return;await api(`/entries/${id}`,{method:'DELETE'});setRows(rs=>rs.filter(r=>r.id!==id));flash('Deleted');};
  if(!rows)return <div className="page"><Spinner/></div>;
  return (<div className="page"><div className="page-head"><div><h1>🗂️ Entries</h1><p className="muted">Security events with AI triage</p></div><button className="btn primary" onClick={()=>setShowForm(s=>!s)}>{showForm?'✕ Close':'+ New Entry'}</button></div><Msg msg={msg}/>{showForm&&<NewEntry onDone={e=>{setRows(rs=>[e,...rs]);setShowForm(false);}} flash={flash}/>}<div className="row filters"><select className="input sm" value={sev} onChange={e=>setSev(e.target.value)}><option value="">All severities</option>{['Critical','High','Medium','Low'].map(s=><option key={s}>{s}</option>)}</select><input className="input sm" placeholder="Search…" value={q} onChange={e=>setQ(e.target.value)}/></div>
    <Card title={`${rows.length} entries`}><table><thead><tr><th>Title</th><th>Type</th><th>Severity</th><th>Score</th><th>Status</th><th>Created</th><th></th></tr></thead><tbody>{rows.map(r=>(<React.Fragment key={r.id}><tr><td className="list-title">{r.title}</td><td><Badge>{r.type}</Badge></td><td><SevBadge sev={r.severity}/></td><td className="mono">{r.threat_score}</td><td><select className="input xs" value={r.status} onChange={e=>setStatus(r.id,e.target.value)}>{STATUSES.map(s=><option key={s}>{s}</option>)}</select></td><td className="muted mono">{fmt(r.created_at)}</td><td className="row nowrap"><button className="btn ghost xs" onClick={()=>doAnalyze(r.id)} disabled={busy===r.id}>{busy===r.id?'…':'⚡'}</button><button className="btn ghost xs" onClick={()=>setOpen(open===r.id?null:r.id)}>{open===r.id?'▲':'▼'}</button><button className="btn ghost xs danger" onClick={()=>del(r.id)}>🗑</button></td></tr>{open===r.id&&<tr><td colSpan="7"><pre className="code">{r.content}</pre>{r.ai_analysis&&<div className="detail"><div className="chip-row">{r.ai_analysis.detections.map((d,i)=><span key={i} className="chip mono">{d.name} [{d.mitre}]</span>)}</div><ol className="rec-list">{r.ai_analysis.recommendations.slice(0,4).map((x,i)=><li key={i}>{x}</li>)}</ol></div>}</td></tr>}</React.Fragment>))}</tbody></table>{rows.length===0&&<div className="muted">No entries match.</div>}</Card>
  </div>);
}
