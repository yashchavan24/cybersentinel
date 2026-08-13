const RULES = [
  { id:'sqli_union', name:'SQL Injection — UNION extraction', mitre:'T1190', weight:26, re:/union[\s\S]{0,30}select/i, advice:'Block source at WAF, verify parameterized queries.' },
  { id:'sqli_basic', name:'SQL Injection — boolean bypass', mitre:'T1190', weight:24, re:/('\s*or\s*'|"\s*or\s*"|or\s+1\s*=\s*1|'\s*;\s*--|sleep\s*\(\s*\d+\s*\))/i, advice:'Block source and confirm parameterized queries.' },
  { id:'xss', name:'Cross-Site Scripting', mitre:'T1059.007', weight:26, re:/(<script[\s\S]{0,40}>|javascript\s*:|on(error|load|click)\s*=|document\.cookie)/i, advice:'Sanitize output, enforce CSP.' },
  { id:'traversal', name:'Path traversal', mitre:'T1083', weight:22, re:/\.\.\//, advice:'Normalize paths, jail web root.' },
  { id:'sensitive_file', name:'Sensitive file targeted', mitre:'T1005', weight:18, re:/\/etc\/(passwd|shadow)|boot\.ini|ntds\.dit/i, advice:'Harden file permissions.' },
  { id:'cmdi', name:'Command injection', mitre:'T1059.003', weight:30, re:/(;|\||&&)\s*(cat|ls|whoami|id|nc|wget|curl|powershell|cmd)\b|powershell\s+-(enc|encodedcommand)/i, advice:'Reject shell metacharacters.' },
  { id:'obfuscation', name:'Obfuscated payload', mitre:'T1027', weight:18, re:/(eval\s*\(|base64_decode|atob\s*\(|frombase64string)/i, advice:'Decode in sandbox.' },
  { id:'brand', name:'Brand impersonation', mitre:'T1566', weight:18, re:/(micr0soft|paypa1|g00gle|arnazon|faceb00k|app1e-id|netf1ix)/i, advice:'Block sender/domain.' },
  { id:'tld', name:'High-risk TLD', mitre:'T1583.001', weight:12, re:/\.(tk|ml|ga|cf|gq|ru|cn|top|xyz)\b/i, advice:'Blocklist domain.' },
  { id:'c2', name:'C2 / beaconing', mitre:'T1071.001', weight:30, re:/(beacon|c2|command.and.control|callback[\s\S]{0,30}(seconds|interval)|cobalt.?strike)/i, advice:'Isolate host, capture PCAP.' },
  { id:'masquerade', name:'Process masquerading', mitre:'T1036.005', weight:20, re:/(svch0st|scvhost|lsasss|expl0rer|taskh0st)/i, advice:'Isolate endpoint.' },
  { id:'macro', name:'Office macro chain', mitre:'T1566.001', weight:16, re:/(winword|excel|powerpnt)\.exe[\s\S]{0,80}(macro|spawned|child process)/i, advice:'Disable macros via GPO.' },
  { id:'scanner', name:'Recon tool UA', mitre:'T1595', weight:15, re:/(sqlmap|nikto|nmap|masscan|dirbuster|acunetix|nessus)/i, advice:'Rate-limit/block.' },
  { id:'cred_exposure', name:'Cleartext credentials', mitre:'T1552', weight:20, re:/(password|passwd|api_key|secret_key|token)\s*[=:]\s*\S+/i, advice:'Rotate credential, scrub logs.' }
];

const isPrivate = ip => /^(10\.|127\.|192\.168\.|169\.254\.|0\.)/.test(ip) || /^172\.(1[6-9]|2\d|3[01])\./.test(ip);
const shannon = s => { const f={}; for(const c of s) f[c]=(f[c]||0)+1; let e=0; for(const k in f){const p=f[k]/s.length; e-=p*Math.log2(p);} return e; };

function extractIOCs(text) {
  const urls=[...new Set(text.match(/https?:\/\/[^\s"'<>()]+/gi)||[])];
  const emails=[...new Set(text.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi)||[])];
  let rest=text; [...urls,...emails].forEach(s=>rest=rest.split(s).join(' '));
  const sha256=[...new Set(rest.match(/\b[a-f0-9]{64}\b/gi)||[])];
  sha256.forEach(h=>rest=rest.split(h).join(' '));
  const md5=[...new Set(rest.match(/\b[a-f0-9]{32}\b/gi)||[])];
  const ipv4=[...new Set(text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)||[])].filter(ip=>ip.split('.').every(o=>+o<=255));
  const domain=[...new Set(rest.match(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi)||[])].filter(d=>!/\.(exe|png|jpg|gif|js|css|log|txt|dll)$/i.test(d)).slice(0,10);
  return {ipv4:ipv4.map(v=>({value:v,internal:isPrivate(v)})),url:urls,email:emails,sha256,md5,domain};
}

export function analyze(content, type='log') {
  const detections=[]; let score=0;
  const push=(r,detail,w=r.weight)=>{detections.push({id:r.id,name:r.name,mitre:r.mitre,weight:w,detail:String(detail||'').slice(0,120)});score+=w;};
  for(const r of RULES){const m=content.match(r.re);if(m)push(r,m[0]);}
  const pkw=['urgent','suspended','verify your','click here','confirm your','deactivat','unusual activity','immediate action','dear customer','final notice'];
  const hits=pkw.filter(k=>content.toLowerCase().includes(k));
  const hasLink=/https?:\/\//.test(content)||/@[a-z0-9.-]+\.[a-z]{2,}/i.test(content);
  if(hits.length>=2&&hasLink)push({id:'phishing',name:'Phishing indicators',mitre:'T1566.002',advice:'Purge email, block sender.'},'keywords: '+hits.slice(0,5).join(', '),Math.min(18+6*hits.length,34));
  const fails=(content.match(/failed (password|login|auth)|authentication failure/gi)||[]).length;
  if(fails>=5)push({id:'bruteforce',name:'Brute-force ('+fails+' failures)',mitre:'T1110.001',advice:'Enforce MFA, block IP.'},fails+' failed auth events',30+Math.min(fails,15));
  const iocs=extractIOCs(content);
  if(iocs.ipv4.some(i=>!i.internal))score+=Math.min(6*iocs.ipv4.filter(i=>!i.internal).length,12);
  const tokens=[...new Set(content.split(/[^a-zA-Z0-9+/=]+/))].filter(t=>t.length>=20);
  const hot=tokens.filter(t=>shannon(t)>=4.2).slice(0,3);
  if(hot.length)push({id:'entropy',name:'High-entropy token',mitre:'T1027',advice:'Submit to sandbox/VT.'},hot[0].slice(0,26)+'...',10);
  score=Math.min(score,100);
  const severity=score>=75?'Critical':score>=50?'High':score>=25?'Medium':'Low';
  const verdictMap={Critical:'High-confidence threat — immediate response required',High:'Likely malicious — prioritize investigation',Medium:'Suspicious — analyst review recommended',Low:'Low risk — likely benign'};
  const verdict=verdictMap[severity];
  const recommendations=[];
  const seen=new Set();
  for(const d of detections){
    const rule=RULES.find(r=>r.id===d.id);
    const adv=(rule&&rule.advice)||d.advice;
    if(adv&&!seen.has(adv)){seen.add(adv);recommendations.push(adv);}
  }
  if(severity==='Critical')recommendations.unshift('Initiate IR playbook: isolate assets and page on-call.');
  else if(severity==='High')recommendations.unshift('Open incident ticket, escalate to Tier-2 within SLA.');
  if(iocs.ipv4.some(i=>!i.internal)||iocs.domain.length)recommendations.push('Push IOCs to blocklists/SIEM.');
  if(!detections.length)recommendations.push('No malicious indicators. Retain for re-scanning.');
  return {score,severity,verdict,detections,iocs,recommendations,engine:'CyberSentinel Hybrid v1',analyzed_at:new Date().toISOString()};
}

export async function enrichWithLLM(content, analysis) {
  const key=process.env.OPENAI_API_KEY;
  if(!key)return null;
  try{
    const detectionNames=analysis.detections.map(d=>d.name).join(', ')||'none';
    const userMsg='Telemetry:\n'+content.slice(0,4000)+'\n\nPre-analysis: score '+analysis.score+'/100, severity '+analysis.severity+', detections: '+detectionNames+', IOCs: '+JSON.stringify(analysis.iocs);
    const res=await fetch('https://api.openai.com/v1/chat/completions',{
      method:'POST',
      headers:{'Content-Type':'application/json','Authorization':'Bearer '+key},
      body:JSON.stringify({
        model:process.env.OPENAI_MODEL||'gpt-4o-mini',
        temperature:0.2,
        max_tokens:300,
        messages:[
          {role:'system',content:'Senior SOC analyst. Given telemetry + pre-analysis, return concise verdict + 3 actions. Max 150 words.'},
          {role:'user',content:userMsg}
        ]
      })
    });
    if(!res.ok)return null;
    const data=await res.json();
    return (data.choices&&data.choices[0]&&data.choices[0].message&&data.choices[0].message.content)||null;
  }catch(e){console.error('LLM enrichment failed:',e.message);return null;}
}