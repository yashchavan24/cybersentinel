import { Router } from 'express';
import { z } from 'zod';
import { db } from './db.js';
import { auth, audit } from './auth.js';
import { analyze, enrichWithLLM } from './ai-engine.js';
import { dispatchAlert, sendTest } from './notify.js';
import { encrypt, decrypt } from './security.js';

export const apiRouter = Router();
apiRouter.use(auth);
const ah = fn => (req,res,next) => Promise.resolve(fn(req,res,next)).catch(next);
const validate = schema => (req,res,next) => { const r=schema.safeParse(req.body); if(!r.success)return res.status(400).json({error:r.error.errors[0].message}); req.body=r.data; next(); };
const parseRow = r => ({...r, ai_analysis: r.ai_analysis ? JSON.parse(r.ai_analysis) : null});
const getEntry = id => { const r=db.prepare('SELECT * FROM entries WHERE id=?').get(id); return r&&parseRow(r); };
const STATUSES=['new','triaged','investigating','mitigated','closed'];
const TYPES=['log','alert','email','ioc','incident'];

async function runAnalysis(entry) {
  const result=analyze(entry.content,entry.type);
  result.llm_narrative=await enrichWithLLM(entry.content,result);
  db.prepare('UPDATE entries SET severity=?,threat_score=?,ai_analysis=?,status=?,updated_at=? WHERE id=?').run(result.severity,result.score,JSON.stringify(result),'triaged',new Date().toISOString(),entry.id);
  return result;
}

apiRouter.get('/dashboard',(req,res)=>{
  const q=(s,...p)=>db.prepare(s).get(...p).c;
  const totals={entries:q('SELECT COUNT(*) c FROM entries'),critical:q("SELECT COUNT(*) c FROM entries WHERE severity='Critical'"),high:q("SELECT COUNT(*) c FROM entries WHERE severity='High'"),open:q("SELECT COUNT(*) c FROM entries WHERE status IN ('new','triaged','investigating')"),resolved:q("SELECT COUNT(*) c FROM entries WHERE status IN ('mitigated','closed')"),receivers:q('SELECT COUNT(*) c FROM receivers WHERE active=1'),alerts:q('SELECT COUNT(*) c FROM notifications')};
  const bySeverity=['Critical','High','Medium','Low'].map(s=>({label:s,value:q('SELECT COUNT(*) c FROM entries WHERE severity=?',s)}));
  const byType=db.prepare('SELECT type,COUNT(*) c FROM entries GROUP BY type ORDER BY c DESC').all();
  const recentEntries=db.prepare('SELECT id,title,type,severity,threat_score,status,created_at FROM entries ORDER BY created_at DESC LIMIT 6').all();
  const recentAlerts=db.prepare('SELECT n.*,r.name receiver_name FROM notifications n LEFT JOIN receivers r ON r.id=n.receiver_id ORDER BY n.created_at DESC LIMIT 6').all();
  res.json({totals,bySeverity,byType,recentEntries,recentAlerts});
});

apiRouter.get('/entries',(req,res)=>{
  const {severity,status,q}=req.query; let sql='SELECT * FROM entries WHERE 1=1'; const p=[];
  if(severity){sql+=' AND severity=?';p.push(severity);} if(status){sql+=' AND status=?';p.push(status);} if(q){sql+=' AND (title LIKE ? OR content LIKE ?)';p.push(`%${q}%`,`%${q}%`);}
  sql+=' ORDER BY created_at DESC LIMIT 200';
  res.json({entries:db.prepare(sql).all(...p).map(parseRow)});
});

const entrySchema=z.object({title:z.string().trim().min(3).max(140),type:z.enum(TYPES).default('log'),content:z.string().trim().min(1).max(50000),source:z.string().trim().max(120).optional().default('manual'),auto_analyze:z.boolean().optional().default(true)});
apiRouter.post('/entries',validate(entrySchema),ah(async(req,res)=>{
  const now=new Date().toISOString();
  const id=db.prepare('INSERT INTO entries (user_id,title,type,content,source,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)').run(req.user.id,req.body.title,req.body.type,req.body.content,req.body.source,'new',now,now).lastInsertRowid;
  let analysis=null,dispatched=[]; const entry=getEntry(id);
  if(req.body.auto_analyze){analysis=await runAnalysis(entry);dispatched=await dispatchAlert(getEntry(id),analysis);}
  audit(req,'ENTRY_CREATE',`#${id} ${req.body.title}`);
  res.json({entry:getEntry(id),analysis,dispatched});
}));

apiRouter.post('/entries/:id/analyze',ah(async(req,res)=>{
  const entry=getEntry(req.params.id); if(!entry)return res.status(404).json({error:'Not found'});
  const analysis=await runAnalysis(entry); const dispatched=await dispatchAlert(getEntry(entry.id),analysis);
  audit(req,'ANALYZE',`entry #${entry.id} → ${analysis.severity}`);
  res.json({entry:getEntry(entry.id),analysis,dispatched});
}));

const quickSchema=z.object({content:z.string().min(1).max(50000),type:z.enum(TYPES).default('log')});
apiRouter.post('/analyze',validate(quickSchema),ah(async(req,res)=>{
  const analysis=analyze(req.body.content,req.body.type); analysis.llm_narrative=await enrichWithLLM(req.body.content,analysis);
  audit(req,'QUICK_ANALYZE',`${req.body.type} ${req.body.content.length} chars`);
  res.json({analysis});
}));

const patchEntry=z.object({title:z.string().trim().min(3).max(140).optional(),status:z.enum(STATUSES).optional(),source:z.string().trim().max(120).optional()}).refine(o=>Object.keys(o).length>0,{message:'No fields'});
apiRouter.patch('/entries/:id',validate(patchEntry),(req,res)=>{
  const entry=db.prepare('SELECT * FROM entries WHERE id=?').get(req.params.id); if(!entry)return res.status(404).json({error:'Not found'});
  const next={...entry,...req.body,updated_at:new Date().toISOString()};
  db.prepare('UPDATE entries SET title=?,status=?,source=?,updated_at=? WHERE id=?').run(next.title,next.status,next.source,next.updated_at,entry.id);
  audit(req,'ENTRY_UPDATE',`#${entry.id}`); res.json({entry:getEntry(entry.id)});
});

apiRouter.delete('/entries/:id',(req,res)=>{
  const info=db.prepare('DELETE FROM entries WHERE id=?').run(req.params.id); if(!info.changes)return res.status(404).json({error:'Not found'});
  audit(req,'ENTRY_DELETE',`#${req.params.id}`); res.json({ok:true});
});

const maskReceiver=r=>({...r,phone:r.phone_enc?'•••••'+(decrypt(r.phone_enc)||'').slice(-3):null,phone_enc:undefined,webhook_url:r.webhook_url||''});
apiRouter.get('/receivers',(req,res)=>{res.json({receivers:db.prepare('SELECT * FROM receivers ORDER BY created_at DESC').all().map(maskReceiver)});});

const receiverSchema=z.object({name:z.string().trim().min(2).max(80),email:z.string().trim().email(),channel:z.enum(['email','sms','webhook']),phone:z.string().trim().max(20).optional().or(z.literal('')),webhook_url:z.string().trim().max(300).optional().or(z.literal('')),critical_only:z.boolean().default(false)});
apiRouter.post('/receivers',validate(receiverSchema),(req,res)=>{
  const b=req.body;
  const id=db.prepare('INSERT INTO receivers (name,email,channel,phone_enc,webhook_url,critical_only,active,created_at) VALUES (?,?,?,?,?,?,1,?)').run(b.name,b.email,b.channel,b.phone?encrypt(b.phone):null,b.webhook_url||null,b.critical_only?1:0,new Date().toISOString()).lastInsertRowid;
  audit(req,'RECEIVER_CREATE',b.name); res.json({receiver:maskReceiver(db.prepare('SELECT * FROM receivers WHERE id=?').get(id))});
});

apiRouter.patch('/receivers/:id',(req,res)=>{
  const r=db.prepare('SELECT * FROM receivers WHERE id=?').get(req.params.id); if(!r)return res.status(404).json({error:'Not found'});
  const {active,critical_only}=z.object({active:z.boolean().optional(),critical_only:z.boolean().optional()}).parse(req.body);
  db.prepare('UPDATE receivers SET active=?,critical_only=? WHERE id=?').run(active===undefined?r.active:(active?1:0),critical_only===undefined?r.critical_only:(critical_only?1:0),r.id);
  audit(req,'RECEIVER_UPDATE',r.name); res.json({receiver:maskReceiver(db.prepare('SELECT * FROM receivers WHERE id=?').get(r.id))});
});

apiRouter.delete('/receivers/:id',(req,res)=>{
  const info=db.prepare('DELETE FROM receivers WHERE id=?').run(req.params.id); if(!info.changes)return res.status(404).json({error:'Not found'});
  audit(req,'RECEIVER_DELETE',`#${req.params.id}`); res.json({ok:true});
});

apiRouter.post('/receivers/:id/test',ah(async(req,res)=>{
  const r=db.prepare('SELECT * FROM receivers WHERE id=?').get(req.params.id); if(!r)return res.status(404).json({error:'Not found'});
  const notification=await sendTest(r); audit(req,'TEST_NOTIFICATION',r.name); res.json({notification});
}));

apiRouter.get('/audit',(req,res)=>{res.json({logs:db.prepare('SELECT * FROM audit_logs ORDER BY id DESC LIMIT 100').all()});});
