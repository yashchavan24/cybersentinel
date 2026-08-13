import 'dotenv/config';
import initSqlJs from 'sql.js';
import bcrypt from 'bcryptjs';
import fs from 'fs';
import { analyze } from './ai-engine.js';
import { encrypt } from './security.js';

fs.mkdirSync('data', { recursive: true });
const DB_PATH = 'data/cybersentinel.db';

// Rock-solid wrapper using sql.js official prepare/step/getAsObject API
function makeWrapper(database, saveFn) {
  const execAll = (sql, params = []) => {
    const stmt = database.prepare(sql);
    try {
      if (params.length) stmt.bind(params);
      const rows = [];
      while (stmt.step()) rows.push(stmt.getAsObject());
      return rows;
    } finally {
      stmt.free();
    }
  };
  return {
    prepare(sql) {
      return {
        run(...params) {
          execAll(sql, params);
          const idRows = execAll("SELECT last_insert_rowid() as id");
          saveFn();
          return { lastInsertRowid: idRows.length ? idRows[0].id : 0, changes: database.getRowsModified() };
        },
        get(...params) {
          const rows = execAll(sql, params);
          return rows.length ? rows[0] : undefined;
        },
        all(...params) {
          return execAll(sql, params);
        }
      };
    },
    exec(sql) { database.run(sql); }
  };
}

export let db = null;

export async function initDB() {
  console.log('⏳ Loading database engine...');
  const SQL = await initSqlJs();
  const rawDb = fs.existsSync(DB_PATH) ? new SQL.Database(fs.readFileSync(DB_PATH)) : new SQL.Database();
  const save = () => fs.writeFileSync(DB_PATH, Buffer.from(rawDb.export()));
  db = makeWrapper(rawDb, save);

  db.exec(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT DEFAULT 'analyst', failed_attempts INTEGER DEFAULT 0, locked_until INTEGER, created_at TEXT)`);
  db.exec(`CREATE TABLE IF NOT EXISTS entries (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT NOT NULL, type TEXT NOT NULL DEFAULT 'log', content TEXT NOT NULL, source TEXT DEFAULT 'manual', status TEXT DEFAULT 'new', severity TEXT, threat_score INTEGER DEFAULT 0, ai_analysis TEXT, created_at TEXT, updated_at TEXT, FOREIGN KEY(user_id) REFERENCES users(id))`);
  db.exec(`CREATE TABLE IF NOT EXISTS receivers (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL, channel TEXT NOT NULL DEFAULT 'email', phone_enc TEXT, webhook_url TEXT, critical_only INTEGER DEFAULT 0, active INTEGER DEFAULT 1, created_at TEXT)`);
  db.exec(`CREATE TABLE IF NOT EXISTS notifications (id INTEGER PRIMARY KEY AUTOINCREMENT, receiver_id INTEGER, entry_id INTEGER, channel TEXT, status TEXT, created_at TEXT)`);
  db.exec(`CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, username TEXT, action TEXT, detail TEXT, ip TEXT, created_at TEXT)`);

  seed();
  save();
  setInterval(save, 5000);
  return db;
}

function seed() {
  const countRow = db.prepare('SELECT COUNT(*) as c FROM users').get();
  if (countRow && countRow.c > 0) { console.log(' Existing database found, skipping seed'); return; }
  console.log('🌱 Seeding demo data...');
  const iso = d => new Date(Date.now() - d * 864e5).toISOString();
  const uidInfo = db.prepare('INSERT INTO users (username,email,password_hash,role,created_at) VALUES (?,?,?,?,?)').run('analyst','analyst@cybersentinel.local',bcrypt.hashSync('Sentinel@2026',12),'admin',iso(6));
  const uid = uidInfo.lastInsertRowid;
  const brute = Array.from({length:12},(_,i)=>`Aug 14 03:2${i%10}:0${i} srv-ssh sshd[44${i}]: Failed password for admin from 203.0.113.77 port ${51200+i} ssh2`).join('\n');
  const samples = [
    {d:0,status:'new',title:'SQLi campaign against /products',type:'log',source:'Apache WAF',content:`203.0.113.42 - - "GET /products?id=41' OR '1'='1 HTTP/1.1" 200\n203.0.113.42 - - "GET /products?id=41 UNION SELECT username, password FROM users-- HTTP/1.1" 200\nUser-Agent: sqlmap/1.8.2`},
    {d:1,status:'new',title:'Phishing: fake Microsoft suspension',type:'email',source:'Mail gateway',content:`From: billing@micr0soft-secure.tk\nSubject: URGENT: Your account will be suspended in 24 hours\n\nDear customer, we detected unusual activity on your account.\nClick here to verify your password immediately: http://login-micr0soft-verify.tk/account\nFailure to confirm will result in permanent deactivation.`},
    {d:1,status:'triaged',title:'SSH brute-force vs admin',type:'log',source:'SSH auth log',content:brute},
    {d:0,status:'new',title:'EDR: svch0st.exe beaconing to C2',type:'alert',source:'EDR',content:`EDR ALERT [WIN-DC01]: process svch0st.exe (PID 5521) spawned from winword.exe macro\nSHA256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\nNetwork: beaconing to update-cdn-metrics.ru every 30 seconds (C2 callback suspected)`},
    {d:3,status:'mitigated',title:'Path traversal blocked at WAF',type:'log',source:'WAF',content:`10.20.4.15 - - "GET /files?path=../../../../etc/passwd HTTP/1.1" 403`},
    {d:5,status:'closed',title:'Normal login — j.doe',type:'log',source:'IAM',content:`INFO 2026-08-09 08:02:11 user=j.doe action=login status=success src=10.0.4.12 session=8h`}
  ];
  const ins = db.prepare('INSERT INTO entries (user_id,title,type,content,source,status,severity,threat_score,ai_analysis,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)');
  const ids = [];
  for (const s of samples) { const a = analyze(s.content, s.type); const r = ins.run(uid, s.title, s.type, s.content, s.source, s.status, a.severity, a.score, JSON.stringify(a), iso(s.d), iso(s.d)); ids.push({id:r.lastInsertRowid, sev:a.severity}); }
  const insR = db.prepare('INSERT INTO receivers (name,email,channel,phone_enc,webhook_url,critical_only,active,created_at) VALUES (?,?,?,?,?,?,?,?)');
  insR.run('Maria Alvarez — SOC Lead','maria.alvarez@corp.io','email',null,'',0,1,iso(6));
  insR.run('On-Call Tier-2','oncall@corp.io','sms',encrypt('+15550132'),'',1,1,iso(6));
  insR.run('Slack #soc-alerts','soc@corp.io','webhook',null,'',0,1,iso(5));
  const insN = db.prepare('INSERT INTO notifications (receiver_id,entry_id,channel,status,created_at) VALUES (?,?,?,?,?)');
  for (const e of ids.filter(x=>['High','Critical'].includes(x.sev))) { insN.run(1,e.id,'email','simulated',iso(0)); insN.run(3,e.id,'webhook','simulated',iso(0)); if(e.sev==='Critical') insN.run(2,e.id,'sms','simulated',iso(0)); }
  db.prepare('INSERT INTO audit_logs (username,action,detail,ip,created_at) VALUES (?,?,?,?,?)').run('system','SEED','Demo workspace initialized','127.0.0.1',iso(6));
  console.log('🌱 Demo data seeded → login: analyst / Sentinel@2026');
}