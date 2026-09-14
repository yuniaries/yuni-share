import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';

function open(root) {
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  const db = new Database(path.join(root, 'enrollment.db'));
  db.exec('CREATE TABLE IF NOT EXISTS codes (email TEXT PRIMARY KEY, digest TEXT NOT NULL, expires INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0)');
  return db;
}
const digest = (email, code) => crypto.createHash('sha256').update(email + ':' + code).digest('hex');
export function issueEnrollment(root, email) {
  email = email.trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error('Valid email required');
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let code;
  do { code = Array.from({length:6}, () => alphabet[crypto.randomInt(alphabet.length)]).join(''); }
  while (!/[A-Z]/.test(code) || !/\d/.test(code));
  const db = open(root);
  try { db.prepare('INSERT OR REPLACE INTO codes(email,digest,expires,attempts) VALUES(?,?,?,0)').run(email,digest(email,code),Date.now()+15*60*1000); }
  finally { db.close(); }
  return code;
}
export function enrollmentRequest(root, action, email, code) {
  if (action !== 'verify') return {ok:false,status:501,error:'请联系此部署的管理员获取一次性注册码；本版本不发送邮件'};
  email = email.trim().toLowerCase();
  const db = open(root);
  try {
    return db.transaction(() => {
      const row=db.prepare('SELECT * FROM codes WHERE email=?').get(email);
      if (!row || row.expires < Date.now() || row.attempts >= 5) return {ok:false,status:401,error:'注册码无效或已过期'};
      db.prepare('UPDATE codes SET attempts=attempts+1 WHERE email=?').run(email);
      if (!crypto.timingSafeEqual(Buffer.from(row.digest,'hex'),Buffer.from(digest(email,code),'hex'))) return {ok:false,status:401,error:'注册码错误'};
      db.prepare('DELETE FROM codes WHERE email=?').run(email);
      return {ok:true,verified:true};
    })();
  } finally { db.close(); }
}
