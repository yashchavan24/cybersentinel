import React, { useState } from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../store.js';
export default function Login() {
  const { user, login, register } = useAuth();
  const [mode,setMode] = useState('login');
  const [f,setF] = useState({username:'',email:'',password:''});
  const [err,setErr] = useState(''); const [busy,setBusy] = useState(false);
  if (user) return <Navigate to="/" replace />;
  const set = k => e => setF({...f,[k]:e.target.value});
  const submit = async e => { e.preventDefault(); setErr(''); setBusy(true); try{mode==='login'?await login(f.username,f.password):await register(f);}catch(ex){setErr(ex.message);}finally{setBusy(false);} };
  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={submit}>
        <div className="logo big">🛡️ CyberSentinel</div>
        <p className="muted center">AI-powered SOC automation · triage · dispatch · audit</p>
        <div className="tabs">
          <button type="button" className={mode==='login'?'tab active':'tab'} onClick={()=>setMode('login')}>Sign in</button>
          <button type="button" className={mode==='register'?'tab active':'tab'} onClick={()=>setMode('register')}>Register</button>
        </div>
        <label>Username<input className="input" value={f.username} onChange={set('username')} required /></label>
        {mode==='register'&&<label>Email<input className="input" type="email" value={f.email} onChange={set('email')} required /></label>}
        <label>Password<input className="input" type="password" value={f.password} onChange={set('password')} required /></label>
        {err&&<div className="flash err">{err}</div>}
        <button className="btn primary block" disabled={busy}>{busy?'Please wait…':mode==='login'?'Access console':'Create account'}</button>
        {mode==='login'&&<div className="hint mono">demo → analyst / Sentinel@2026</div>}
      </form>
    </div>
  );
}
