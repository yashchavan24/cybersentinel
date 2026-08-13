import React, { useEffect, useState } from 'react';
import { BrowserRouter, Routes, Route, Navigate, Outlet, NavLink } from 'react-router-dom';
import { AuthCtx, useAuth } from './store.js';
import { api, setToken, getToken } from './api.js';
import Login from './pages/Login.jsx';
import Dashboard from './pages/Dashboard.jsx';
import Analyzer from './pages/Analyzer.jsx';
import Entries from './pages/Entries.jsx';
import Receivers from './pages/Receivers.jsx';
import Audit from './pages/Audit.jsx';

const NAV = [['/','📊','Dashboard'],['/analyzer','⚡','AI Analyzer'],['/entries','🗂️','Entries'],['/receivers','📡','Receivers'],['/audit','🧾','Audit Log']];

function Shell() {
  const { user, logout } = useAuth();
  if (!user) return <Navigate to="/login" replace />;
  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="logo">🛡️ CyberSentinel</div>
        <nav>{NAV.map(([to,icon,label])=><NavLink key={to} to={to} end={to==='/'} className={({isActive})=>'nav-link'+(isActive?' active':'')}><span>{icon}</span><span className="nav-txt">{label}</span></NavLink>)}</nav>
        <div className="sidebar-foot">
          <div className="engine-dot"><span className="dot" />AI engine online</div>
          <div className="user-chip"><div className="avatar">{user.username[0].toUpperCase()}</div><div className="nav-txt"><div className="u-name">{user.username}</div><div className="u-role">{user.role}</div></div></div>
          <button className="btn ghost sm block" onClick={logout}>Sign out</button>
        </div>
      </aside>
      <main className="main"><Outlet /></main>
    </div>
  );
}

export default function App() {
  const [user,setUser] = useState(null);
  const [booting,setBooting] = useState(true);
  useEffect(() => { (async () => { if(getToken()){try{setUser((await api('/auth/me')).user);}catch{setToken(null);}} setBooting(false); })(); }, []);
  const login = async (username,password) => { const d=await api('/auth/login',{method:'POST',body:{username,password}}); setToken(d.token); setUser(d.user); };
  const register = async form => { const d=await api('/auth/register',{method:'POST',body:form}); setToken(d.token); setUser(d.user); };
  const logout = () => { setToken(null); setUser(null); };
  if (booting) return <div className="splash"><div className="spinner" /><div className="muted">Authenticating…</div></div>;
  return (
    <AuthCtx.Provider value={{user,login,register,logout}}>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route element={<Shell />}>
            <Route index element={<Dashboard />} />
            <Route path="analyzer" element={<Analyzer />} />
            <Route path="entries" element={<Entries />} />
            <Route path="receivers" element={<Receivers />} />
            <Route path="audit" element={<Audit />} />
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthCtx.Provider>
  );
}
