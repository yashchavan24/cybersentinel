import React, { useEffect, useState } from 'react';
import { api } from '../api.js';
import { Card, Spinner, Badge, Msg } from '../components.jsx';
const CH_COLOR = {email:'#22d3ee',sms:'#34d399',webhook:'#a78bfa'};
export default function Receivers() {
  const [list,setList]=useState(null); const [msg,setMsg]=useState('');
  const [f,setF]=useState({name:'',email:'',channel:'email',phone:'',webhook_url:'',critical_only:false});
  const [busy,setBusy]=useState(false);
  const flash=m=>{setMsg(m);setTimeout(()=>setMsg(''),4000);};
  const load=()=>api('/receivers').then(d=>setList(d.receivers)).catch(e=>flash('⚠ '+e.message));
  useEffect(()=>{load();},[]);
  const set=k=>e=>setF({...f,[k]:e.type==='checkbox'?e.target.checked:e.target.value});
  const create=async e=>{e.preventDefault();setBusy(true);try{await api('/receivers',{method:'POST',body:f});flash('✅ Added');setF({name:'',email:'',channel:'email',phone:'',webhook_url:'',critical_only:false});load();}catch(ex){flash('⚠ '+ex.message);}finally{setBusy(false);}};
  const toggle=async r=>{try{await api(`/receivers/${r.id}`,{method:'PATCH',body:{active:!r.active}});load();}catch(e){flash('⚠ '+e.message);}};
  const test=async r=>{try{const d=await api(`/receivers/${r.id}/test`,{method:'POST'});flash(`📨 Test ${d.notification.status} → ${d.notification.receiver}`);}catch(e){flash('⚠ '+e.message);}};
  const del=async r=>{if(!confirm(`Remove ${r.name}?`))return;await api(`/receivers/${r.id}`,{method:'DELETE'});load();};
  if(!list)return <div className="page"><Spinner/></div>;
  return (<div className="page"><h1>📡 Receivers</h1><p className="muted">Notification targets. Phones stored AES-256-GCM encrypted.</p><Msg msg={msg}/>
    <Card title="Add Receiver"><form onSubmit={create} className="form-grid"><div className="row"><input className="input" placeholder="Name" value={f.name} onChange={set('name')} required/><input className="input" type="email" placeholder="Email" value={f.email} onChange={set('email')} required/><select className="input" value={f.channel} onChange={set('channel')}>{['email','sms','webhook'].map(c=><option key={c}>{c}</option>)}</select></div><div className="row">{f.channel==='sms'&&<input className="input" placeholder="+15550123456" value={f.phone} onChange={set('phone')}/>}{f.channel==='webhook'&&<input className="input" placeholder="https://hooks.slack.com/…" value={f.webhook_url} onChange={set('webhook_url')}/>}<label className="check"><input type="checkbox" checked={f.critical_only} onChange={set('critical_only')}/> Critical only</label><button className="btn primary" disabled={busy}>{busy?'Saving…':'+ Add'}</button></div></form></Card>
    <div className="recv-grid">{list.map(r=><div key={r.id} className={'recv-card'+(r.active?'':' dim')}><div className="recv-head"><b>{r.name}</b><span className={'dot '+(r.active?'on':'off')}/></div><div className="row wrap"><Badge color={CH_COLOR[r.channel]}>{r.channel}</Badge>{r.critical_only&&<Badge color="var(--red)">critical-only</Badge>}</div><div className="muted mono small">{r.email}</div>{r.phone&&<div className="muted mono small">📱 {r.phone} 🔒</div>}{r.webhook_url&&<div className="muted mono small truncate">🔗 {r.webhook_url}</div>}<div className="row nowrap"><button className="btn ghost xs" onClick={()=>test(r)}>📨 Test</button><button className="btn ghost xs" onClick={()=>toggle(r)}>{r.active?'Pause':'Activate'}</button><button className="btn ghost xs danger" onClick={()=>del(r)}>🗑</button></div></div>)}</div>
  </div>);
}
