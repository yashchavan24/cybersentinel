import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api.js';
import { Card, Spinner, SevBadge, fmt, SEV_COLORS } from '../components.jsx';
const Stat = ({label,value,color}) => <div className="stat"><div className="num" style={{color}}>{value}</div><div className="lbl">{label}</div></div>;
function Donut({data}) {
  const total=data.reduce((s,d)=>s+d.value,0); const r=54,c=2*Math.PI*r; let acc=0;
  return (<div className="donut-wrap"><svg viewBox="0 0 140 140" width="150" height="150"><circle cx="70" cy="70" r={r} fill="none" stroke="#16233c" strokeWidth="15"/>{total>0&&data.filter(d=>d.value>0).map((d,i)=>{const frac=d.value/total,dash=frac*c,off=-acc*c;acc+=frac;return <circle key={i} cx="70" cy="70" r={r} fill="none" stroke={SEV_COLORS[d.label]} strokeWidth="15" strokeDasharray={`${dash} ${c-dash}`} strokeDashoffset={off} transform="rotate(-90 70 70)"/>;})}<text x="70" y="67" textAnchor="middle" className="donut-num">{total}</text><text x="70" y="86" textAnchor="middle" className="donut-lbl">events</text></svg><div className="legend">{data.map(d=><div key={d.label} className="legend-row"><span className="dotc" style={{background:SEV_COLORS[d.label]}}/>{d.label}<b>{d.value}</b></div>)}</div></div>);
}
export default function Dashboard() {
  const [d,setD]=useState(null); const [err,setErr]=useState('');
  useEffect(()=>{api('/dashboard').then(setD).catch(e=>setErr(e.message));},[]);
  if(err)return <div className="page"><div className="flash err">{err}</div></div>;
  if(!d)return <div className="page"><Spinner/></div>;
  const t=d.totals; const max=Math.max(...d.byType.map(x=>x.c),1);
  return (<div className="page"><h1>SOC Overview</h1><p className="muted">Security posture across monitored telemetry · {new Date().toDateString()}</p>
    <div className="stat-grid"><Stat label="Total Events" value={t.entries} color="var(--cyan)"/><Stat label="Critical" value={t.critical} color="var(--red)"/><Stat label="High" value={t.high} color="var(--orange)"/><Stat label="Open Cases" value={t.open} color="var(--amber)"/><Stat label="Resolved" value={t.resolved} color="var(--green)"/><Stat label="Alerts Sent" value={t.alerts} color="var(--purple)"/></div>
    <div className="grid-2"><Card title="Severity Distribution"><Donut data={d.bySeverity}/></Card><Card title="Events by Type">{d.byType.map(x=><div key={x.type} className="bar-row"><span className="bar-lbl mono">{x.type}</span><div className="bar"><div style={{width:`${x.c/max*100}%`}}/></div><b>{x.c}</b></div>)}</Card></div>
    <div className="grid-2"><Card title="Recent Events" actions={<Link className="link" to="/entries">view all →</Link>}>{d.recentEntries.map(e=><div key={e.id} className="list-row"><SevBadge sev={e.severity}/><span className="list-title">{e.title}</span><span className="muted mono">{e.threat_score}</span><span className="muted mono">{fmt(e.created_at)}</span></div>)}</Card><Card title="Recent Alert Dispatches">{d.recentAlerts.length===0&&<div className="muted">No dispatches yet</div>}{d.recentAlerts.map(n=><div key={n.id} className="list-row"><span className="list-title">{n.receiver_name||'—'}</span><span className="badge">{n.channel}</span><span className={'mono '+(n.status==='failed'?'err-txt':'ok-txt')}>{n.status}</span><span className="muted mono">{fmt(n.created_at)}</span></div>)}</Card></div>
  </div>);
}
