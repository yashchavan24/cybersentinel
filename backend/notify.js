import { db } from './db.js';
async function postWebhook(url, payload) {
  const ctrl=new AbortController(); const t=setTimeout(()=>ctrl.abort(),5000);
  try{const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload),signal:ctrl.signal});return r.ok?'sent':'failed';}
  catch{return 'failed';}finally{clearTimeout(t);}
}
export async function dispatchAlert(entry, analysis) {
  if(!['High','Critical'].includes(analysis.severity))return[];
  const now=new Date().toISOString(); const out=[];
  for(const r of db.prepare('SELECT * FROM receivers WHERE active=1').all()){
    if(r.critical_only&&analysis.severity!=='Critical')continue;
    const payload={source:'CyberSentinel',severity:analysis.severity,score:analysis.score,verdict:analysis.verdict,entry_id:entry.id,title:entry.title,time:now};
    let status='simulated';
    if(r.channel==='webhook'&&r.webhook_url)status=await postWebhook(r.webhook_url,payload);
    db.prepare('INSERT INTO notifications (receiver_id,entry_id,channel,status,created_at) VALUES (?,?,?,?,?)').run(r.id,entry.id,r.channel,status,now);
    out.push({receiver:r.name,channel:r.channel,status});
  }
  return out;
}
export async function sendTest(receiver) {
  const now=new Date().toISOString();
  const payload={source:'CyberSentinel',type:'test',message:`Test alert for ${receiver.name}`,time:now};
  let status='simulated';
  if(receiver.channel==='webhook'&&receiver.webhook_url)status=await postWebhook(receiver.webhook_url,payload);
  db.prepare('INSERT INTO notifications (receiver_id,entry_id,channel,status,created_at) VALUES (?,?,?,?,?)').run(receiver.id,null,receiver.channel,status,now);
  return {receiver:receiver.name,channel:receiver.channel,status};
}
