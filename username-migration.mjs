// User IDs and unique email addresses remain account identities. Names are display-only.
export async function migrateDisplayNames(db, backupPath) {
  const original = db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'").get()?.sql;
  if (!original || !/username TEXT NOT NULL UNIQUE COLLATE NOCASE/i.test(original)) return false;
  await db.backup(backupPath);
  const objects = db.prepare("SELECT sql FROM sqlite_master WHERE tbl_name='users' AND type IN ('index','trigger') AND sql IS NOT NULL").all();
  const quote = value => '"' + value.replaceAll('"','""') + '"';
  const columns = db.pragma('table_info(users)').map(c => quote(c.name)).join(',');
  const count = db.prepare('SELECT count(*) AS n FROM users').get().n;
  db.pragma('foreign_keys = OFF');
  try {
    db.transaction(() => {
      db.exec(original.replace(/CREATE TABLE\s+(?:"users"|users)/i, 'CREATE TABLE users_display_migration').replace(/username TEXT NOT NULL UNIQUE COLLATE NOCASE/i, 'username TEXT NOT NULL COLLATE NOCASE'));
      db.exec(`INSERT INTO users_display_migration (${columns}) SELECT ${columns} FROM users`);
      if (db.prepare('SELECT count(*) AS n FROM users_display_migration').get().n !== count) throw Error('User count mismatch');
      db.exec('DROP TABLE users; ALTER TABLE users_display_migration RENAME TO users');
      for (const object of objects) db.exec(object.sql);
      if (db.pragma('foreign_key_check').length) throw Error('Foreign key validation failed');
      if (db.pragma('integrity_check', {simple:true}) !== 'ok') throw Error('Database integrity check failed');
    })();
  } finally { db.pragma('foreign_keys = ON'); }
  return true;
}
