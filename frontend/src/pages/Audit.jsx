import React, { useEffect, useState } from 'react';
import { api } from '../api.js';
import { Card, Spinner, fmt } from '../components.jsx';
export default function Audit() {
  const [logs,setLogs]=useState(null);
  useEffect(()=>{api('/audit').then(d=>setLogs(d.logs)).catch(()=>setLogs([]));},[]);
  if(!logs)return <div className="page"><Spinner/></div>;
  return (<div className="page"><h1>🧾 Audit Trail</h1><p className="muted">Every auth event and mutation recorded.</p>
    <Card title={`${logs.length} events`}><table><thead><tr><th>Time</th><th>User</th><th>Action</th><th>Detail</th><th>IP</th></tr></thead><tbody>{logs.map(l=><tr key={l.id}><td className="muted mono nowrap">{fmt(l.created_at)}</td><td className="mono">{l.username}</td><td><span className={'mono '+(l.action.includes('FAIL')?'err-txt':'ok-txt')}>{l.action}</span></td><td className="muted small">{l.detail}</td><td className="muted mono">{l.ip}</td></tr>)}</tbody></table></Card>
  </div>);
}
