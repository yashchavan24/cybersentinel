import React from 'react';
export const SEV_COLORS = { Low:'#34d399', Medium:'#fbbf24', High:'#fb923c', Critical:'#f87171' };
export const Badge = ({children,color='#22d3ee'}) => <span className="badge" style={{color,borderColor:color+'66',background:color+'1a'}}>{children}</span>;
export const SevBadge = ({sev}) => sev ? <Badge color={SEV_COLORS[sev]||'#8294ad'}>{sev}</Badge> : <span className="muted">—</span>;
export const Card = ({title,children,actions}) => <div className="card"><div className="card-head"><h3>{title}</h3>{actions}</div>{children}</div>;
export const Spinner = () => <div className="spinner" />;
export const Msg = ({msg}) => msg ? <div className="flash">{msg}</div> : null;
export const fmt = iso => iso ? new Date(iso).toLocaleString(undefined,{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'}) : '—';
