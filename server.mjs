import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import bcrypt from 'bcryptjs';
import Database from 'better-sqlite3';
import { migrateDisplayNames } from './username-migration.mjs';
import express from 'express';
import helmet from 'helmet';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse
} from '@simplewebauthn/server';
import { createMembershipExpiryReminderService } from './membership-expiry.mjs';

const PORT = Number(process.env.PORT || 8191);
const DATA_ROOT = path.resolve(process.env.DATA_ROOT || './data');
const FILE_ROOT = path.join(DATA_ROOT, 'files');
const TEMP_ROOT = path.join(DATA_ROOT, 'tmp');
const AVATAR_ROOT = path.join(DATA_ROOT, 'avatars');
const DB_PATH = path.join(DATA_ROOT, 'share.db');
const PUBLIC_URL = (process.env.PUBLIC_URL || 'http://localhost:8191').replace(/\/$/, '');
const INVITE_CODE = process.env.INVITE_CODE || '';
// Keep the invite configuration available for a future limited rollout, but
// leave public registration open for the current service.
const INVITE_REGISTRATION_ENABLED = false;
const MAIL_API_URL = process.env.MAIL_API_URL || '';
const MAIL_API_TOKEN = process.env.MAIL_API_TOKEN || '';
const MAIL_SCOPE = process.env.MAIL_SCOPE || 'yuni-share-registration-v1';
const TRANSACTIONAL_MAIL_API_URL = process.env.MAIL_TRANSACTIONAL_API_URL
  || MAIL_API_URL.replace(/\/v1\/recovery-email(?:\?.*)?$/, '/v1/transactional-email');
const USER_QUOTA = Number(process.env.USER_QUOTA_BYTES || 5 * 1024 ** 3);
const PAYMENT_API_ROOT = String(process.env.PAYMENT_API_ROOT || '').replace(/\/$/, '');
const PAYMENT_MERCHANT_NUM = String(process.env.PAYMENT_MERCHANT_NUM || '');
const PAYMENT_SECRET = String(process.env.PAYMENT_SECRET || '');
const PAYMENT_PAY_TYPE = String(process.env.PAYMENT_PAY_TYPE || 'alipay');
const PAYMENT_ENABLED = Boolean(PAYMENT_API_ROOT && PAYMENT_MERCHANT_NUM && PAYMENT_SECRET);
// Administrator access is intentionally separate from customer accounts.  Do
// not reuse a share_session or a customer password for the management console.
const ADMIN_USERNAME = String(process.env.ADMIN_USERNAME || 'admin').trim();
const ADMIN_PASSWORD = String(process.env.ADMIN_PASSWORD || '');
const ADMIN_SESSION_TTL = 8 * 60 * 60 * 1000;
const ADMIN_AUDIT_RETENTION = 7 * 24 * 60 * 60 * 1000;
const ADMIN_AUDIT_CLEANUP_INTERVAL = 24 * 60 * 60 * 1000;
const ADMIN_AUDIT_PAGE_SIZE = 20;
const ADMIN_USER_PAGE_SIZE = 20;
const PLANS = {
  lite: { name: '加密空间 50GB', quota: 50 * 1024 ** 3, monthly: 990, yearly: 9900 },
  plus: { name: '加密空间 200GB', quota: 200 * 1024 ** 3, monthly: 2990, yearly: 29900 },
  pro: { name: '加密空间 2TB', quota: 2 * 1024 ** 4, monthly: 16800, yearly: 168000 },
  max: { name: '加密空间 6TB', quota: 6 * 1024 ** 4, monthly: 49800, yearly: 498000 },
  vault: { name: '加密空间 12TB', quota: 12 * 1024 ** 4, monthly: 99800, yearly: 998000 },
};
const STORAGE_ADDONS = {
  storage_50: { name: '额外加密空间 50GB', quota: 50 * 1024 ** 3, monthly: 990 },
  storage_200: { name: '额外加密空间 200GB', quota: 200 * 1024 ** 3, monthly: 2990 },
  storage_2000: { name: '额外加密空间 2TB', quota: 2 * 1024 ** 4, monthly: 16800 },
  storage_6000: { name: '额外加密空间 6TB', quota: 6 * 1024 ** 4, monthly: 49800 },
  storage_12000: { name: '额外加密空间 12TB', quota: 12 * 1024 ** 4, monthly: 99800 },
};
// Requests stay short enough for proxied slow links; the file itself has no
// separate size cap beyond the account quota and available server storage.
const CHUNK_SIZE = 16 * 1024 ** 2;
const PREVIOUS_CHUNK_SIZE = 4 * 1024 ** 2;
const DISK_RESERVE = Number(process.env.DISK_RESERVE_BYTES || 3 * 1024 ** 3);
const SESSION_TTL = 30 * 24 * 60 * 60 * 1000;
const UPLOAD_TTL = 7 * 24 * 60 * 60 * 1000;
const CANCELLATION_TTL = 10 * 60 * 1000;
const PAID_STORAGE_GRACE_MS = 15 * 24 * 60 * 60 * 1000;
const ENCRYPTION_VERSION = 1;
const LISTING_CATEGORIES = new Set([
  'image', 'video', 'audio', 'pdf', 'document', 'spreadsheet',
  'presentation', 'archive', 'code', 'other'
]);
const GCM_TAG_BYTES = 16;
const VAULT_KDF_ITERATIONS = 600_000;
const ENCRYPTED_METADATA_MAX_LENGTH = 12_000;
const ACCOUNT_DELETION_CHECK_INTERVAL = 60 * 1000;
const PASSWORD_RESET_TTL = 15 * 60 * 1000;
const PASSKEY_CHALLENGE_TTL = 5 * 60 * 1000;
const VAULT_RECOVERY_RESET_PROOF_TTL = 5 * 60 * 1000;
const PUBLIC_ORIGIN = new URL(PUBLIC_URL).origin;
const WEBAUTHN_RP_ID = process.env.WEBAUTHN_RP_ID || new URL(PUBLIC_URL).hostname;
const ANDROID_APP_CERT_SHA256 = '41:A7:95:D7:7B:68:58:7B:B4:D4:A0:42:85:B9:1F:CD:06:1D:66:DC:2E:00:3E:C7:F0:16:36:03:6F:26:A2:F6';
const ANDROID_APP_ORIGIN = 'android:apk-key-hash:QaeV13toWHu01KBChbkfzQYdZtwuAD7H8BY2A28movY';
const USER_PASSKEY_ORIGINS = [PUBLIC_ORIGIN, ANDROID_APP_ORIGIN, 'android:apk-key-hash:44U4pX6JAJI21-K8Hv5IGXEvlqU6sA3cBgiyX4RTFBo'];
const VAULT_PASSKEY_PRF_INPUT = crypto.createHash('sha256')
  .update('yuni-share:vault-passkey-prf:v1')
  .digest('base64url');
const STORAGE_API_URL = String(process.env.STORAGE_API_URL || '').replace(/\/$/, '');
const STORAGE_API_TOKEN = String(process.env.STORAGE_API_TOKEN || '');
const STORAGE_POOL_ID = String(process.env.STORAGE_POOL_ID || '');
const STORAGE_ENABLED = Boolean(STORAGE_API_URL && STORAGE_API_TOKEN);
const SITE_CONTENT_DEFINITIONS = new Map([
  ['terms', { label: '服务条款', fileName: 'terms.html', route: '/terms' }],
  ['user-agreement', { label: '用户协议', fileName: 'user-agreement.html', route: '/user-agreement' }],
  ['privacy', { label: '隐私政策', fileName: 'privacy.html', route: '/privacy' }],
  ['disclaimer', { label: '免责声明', fileName: 'disclaimer.html', route: '/disclaimer' }],
  ['announcement', { label: '站内公告', fileName: null, route: null }]
]);
const SITE_CONTENT_KEYS = new Set(SITE_CONTENT_DEFINITIONS.keys());

await fsp.mkdir(FILE_ROOT, { recursive: true });
await fsp.mkdir(TEMP_ROOT, { recursive: true });
await fsp.mkdir(AVATAR_ROOT, { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
await migrateDisplayNames(db, path.join(DATA_ROOT, 'before-display-names-' + Date.now() + '.db'));
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    public_id TEXT NOT NULL,
    username TEXT NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    quota_bytes INTEGER NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    upload_id TEXT,
    original_name TEXT NOT NULL,
    stored_name TEXT NOT NULL UNIQUE,
    mime_type TEXT NOT NULL,
    size INTEGER NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS files_user_created ON files(user_id, created_at DESC);
  CREATE TABLE IF NOT EXISTS encrypted_folders (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_metadata TEXT NOT NULL,
    encrypted_metadata_iv TEXT NOT NULL,
    is_root INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS encrypted_folders_user_created
    ON encrypted_folders(user_id, created_at ASC);
  CREATE TABLE IF NOT EXISTS uploads (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    original_name TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    size INTEGER NOT NULL,
    chunk_size INTEGER NOT NULL,
    chunk_count INTEGER NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS account_deletions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    email TEXT NOT NULL,
    username TEXT NOT NULL,
    retention_days INTEGER NOT NULL CHECK(retention_days IN (30, 60)),
    requested_at INTEGER NOT NULL,
    scheduled_for INTEGER NOT NULL,
    cancellation_token_hash TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK(status IN ('scheduled', 'erased_pending_notification')),
    completed_at INTEGER
  );
  CREATE INDEX IF NOT EXISTS account_deletions_due ON account_deletions(status, scheduled_for);
  CREATE UNIQUE INDEX IF NOT EXISTS account_deletions_scheduled_user
    ON account_deletions(user_id) WHERE status = 'scheduled';
  CREATE TABLE IF NOT EXISTS password_resets (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS password_resets_user ON password_resets(user_id);
  CREATE INDEX IF NOT EXISTS password_resets_expiry ON password_resets(expires_at);
  CREATE TABLE IF NOT EXISTS vault_passkeys (
    credential_id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key TEXT NOT NULL,
    counter INTEGER NOT NULL DEFAULT 0,
    transports TEXT NOT NULL DEFAULT '[]',
    attachment TEXT NOT NULL DEFAULT 'unknown',
    device_type TEXT NOT NULL DEFAULT 'unknown',
    backed_up INTEGER NOT NULL DEFAULT 0,
    wrapper_salt TEXT,
    wrapper_iv TEXT,
    wrapped_key TEXT,
    state TEXT NOT NULL CHECK(state IN ('pending', 'active')),
    created_at INTEGER NOT NULL,
    last_used_at INTEGER,
    activated_at INTEGER
  );
  CREATE INDEX IF NOT EXISTS vault_passkeys_user_state ON vault_passkeys(user_id, state, created_at DESC);
  CREATE TABLE IF NOT EXISTS vault_passkey_challenges (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_hash TEXT NOT NULL,
    purpose TEXT NOT NULL CHECK(purpose IN ('register', 'activate', 'unlock')),
    challenge TEXT NOT NULL,
    credential_id TEXT,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS vault_passkey_challenges_expiry ON vault_passkey_challenges(expires_at);
  CREATE TABLE IF NOT EXISTS vault_recovery_reset_proofs (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_hash TEXT NOT NULL,
    credential_id TEXT NOT NULL REFERENCES vault_passkeys(credential_id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS vault_recovery_reset_proofs_expiry
    ON vault_recovery_reset_proofs(expires_at);
  CREATE TABLE IF NOT EXISTS passkey_action_challenges (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_hash TEXT NOT NULL,
    purpose TEXT NOT NULL,
    challenge TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS passkey_action_challenges_expiry ON passkey_action_challenges(expires_at);
  CREATE TABLE IF NOT EXISTS passkey_action_proofs (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_hash TEXT NOT NULL,
    credential_id TEXT NOT NULL REFERENCES vault_passkeys(credential_id) ON DELETE CASCADE,
    purpose TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS passkey_action_proofs_expiry ON passkey_action_proofs(expires_at);
  CREATE TABLE IF NOT EXISTS passkey_login_challenges (
    id TEXT PRIMARY KEY,
    challenge TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS passkey_login_challenges_expiry
    ON passkey_login_challenges(expires_at);
  CREATE TABLE IF NOT EXISTS subscriptions (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    plan_id TEXT NOT NULL,
    quota_bytes INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS storage_addons (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    addon_id TEXT NOT NULL,
    quota_bytes INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS payment_orders (
    order_no TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    plan_id TEXT NOT NULL,
    billing_cycle TEXT NOT NULL CHECK(billing_cycle IN ('monthly','yearly')),
    amount_cents INTEGER NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending','paid','expired')),
    created_at INTEGER NOT NULL,
    paid_at INTEGER,
    platform_order_no TEXT
  );
  CREATE INDEX IF NOT EXISTS payment_orders_user_created ON payment_orders(user_id, created_at DESC);
  CREATE TABLE IF NOT EXISTS admin_sessions (
    token_hash TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS admin_audit_logs (
    id INTEGER PRIMARY KEY,
    action TEXT NOT NULL,
    target_user_id INTEGER NOT NULL,
    details TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS admin_audit_logs_target_created ON admin_audit_logs(target_user_id, created_at DESC);
  CREATE INDEX IF NOT EXISTS admin_audit_logs_created ON admin_audit_logs(created_at DESC, id DESC);
  CREATE TABLE IF NOT EXISTS admin_passkeys (
    credential_id TEXT PRIMARY KEY,
    public_key TEXT NOT NULL,
    counter INTEGER NOT NULL DEFAULT 0,
    transports TEXT NOT NULL DEFAULT '[]',
    created_at INTEGER NOT NULL,
    last_used_at INTEGER
  );
  CREATE TABLE IF NOT EXISTS admin_passkey_challenges (
    id TEXT PRIMARY KEY,
    purpose TEXT NOT NULL CHECK(purpose IN ('register','login')),
    challenge TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS admin_passkey_challenges_expiry ON admin_passkey_challenges(expires_at);
  CREATE TABLE IF NOT EXISTS site_content (
    content_key TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    intro TEXT NOT NULL DEFAULT '',
    meta TEXT NOT NULL DEFAULT '',
    body_html TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    updated_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS site_content_revisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content_key TEXT NOT NULL,
    title TEXT NOT NULL,
    intro TEXT NOT NULL,
    meta TEXT NOT NULL,
    body_html TEXT NOT NULL,
    enabled INTEGER NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS site_content_revisions_key_created
    ON site_content_revisions(content_key, created_at DESC, id DESC);
`);
if (!db.prepare('PRAGMA table_info(users)').all().some(column => column.name === 'email')) {
  db.exec('ALTER TABLE users ADD COLUMN email TEXT');
}
if (!db.prepare('PRAGMA table_info(uploads)').all().some(column => column.name === 'chunk_size')) {
  db.exec('ALTER TABLE uploads ADD COLUMN chunk_size INTEGER');
  db.prepare('UPDATE uploads SET chunk_size = ? WHERE chunk_size IS NULL').run(PREVIOUS_CHUNK_SIZE);
}
if (!db.prepare('PRAGMA table_info(files)').all().some(column => column.name === 'upload_id')) {
  db.exec('ALTER TABLE files ADD COLUMN upload_id TEXT');
}
function addColumnIfMissing(table, definition) {
  const name = definition.split(/\s+/)[0];
  if (!db.prepare(`PRAGMA table_info(${table})`).all().some(column => column.name === name)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${definition}`);
  }
}

addColumnIfMissing('users', 'public_id TEXT');
db.transaction(() => {
  const assigned = new Set(db.prepare(`SELECT public_id FROM users
    WHERE public_id IS NOT NULL AND trim(public_id) != ''`).all().map(row => row.public_id));
  const missing = db.prepare(`SELECT id FROM users
    WHERE public_id IS NULL OR trim(public_id) = ''`).all();
  const update = db.prepare(`UPDATE users SET public_id = ?
    WHERE id = ? AND (public_id IS NULL OR trim(public_id) = '')`);
  for (const user of missing) {
    let publicId;
    do { publicId = crypto.randomUUID(); } while (assigned.has(publicId));
    update.run(publicId, user.id);
    assigned.add(publicId);
  }
})();
db.exec(`
  CREATE UNIQUE INDEX IF NOT EXISTS users_public_id_unique ON users(public_id);
  CREATE TRIGGER IF NOT EXISTS users_public_id_required
  BEFORE INSERT ON users
  FOR EACH ROW WHEN NEW.public_id IS NULL OR trim(NEW.public_id) = ''
  BEGIN
    SELECT RAISE(ABORT, 'users.public_id is required');
  END;
  CREATE TRIGGER IF NOT EXISTS users_public_id_immutable
  BEFORE UPDATE OF public_id ON users
  FOR EACH ROW WHEN NEW.public_id IS NOT OLD.public_id
  BEGIN
    SELECT RAISE(ABORT, 'users.public_id is immutable');
  END;
`);

const storageAddonColumns = db.prepare('PRAGMA table_info(storage_addons)').all();
if (!storageAddonColumns.some(column => column.name === 'id')) {
  db.transaction(() => {
    db.exec(`
      ALTER TABLE storage_addons RENAME TO storage_addons_legacy;
      CREATE TABLE storage_addons (
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        addon_id TEXT NOT NULL,
        quota_bytes INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );
      INSERT INTO storage_addons(user_id, addon_id, quota_bytes, expires_at, created_at, updated_at)
        SELECT user_id, addon_id, quota_bytes, expires_at, updated_at, updated_at FROM storage_addons_legacy;
      DROP TABLE storage_addons_legacy;
    `);
  })();
}

// The server stores only the password-wrapped vault key. It never receives the
// unwrapped vault key or a file's plaintext encryption key.
addColumnIfMissing('users', 'encryption_version INTEGER NOT NULL DEFAULT 0');
addColumnIfMissing('users', 'vault_salt TEXT');
addColumnIfMissing('users', 'vault_key_iv TEXT');
addColumnIfMissing('users', 'vault_wrapped_key TEXT');
addColumnIfMissing('users', 'vault_kdf_iterations INTEGER');
addColumnIfMissing('users', 'vault_recovery_iv TEXT');
addColumnIfMissing('users', 'vault_recovery_wrapped_key TEXT');
addColumnIfMissing('users', 'vault_recovery_salt TEXT');
addColumnIfMissing('users', 'vault_recovery_kdf_iterations INTEGER');
addColumnIfMissing('users', 'avatar_path TEXT');
addColumnIfMissing('users', 'storage_overage_since INTEGER');
addColumnIfMissing('payment_orders', 'pay_url TEXT');
addColumnIfMissing('payment_orders', "order_type TEXT NOT NULL DEFAULT 'subscription'");
addColumnIfMissing('files', 'encryption_version INTEGER NOT NULL DEFAULT 0');
addColumnIfMissing('files', 'encrypted_metadata TEXT');
addColumnIfMissing('files', 'encrypted_metadata_iv TEXT');
addColumnIfMissing('files', 'chunk_size INTEGER');
addColumnIfMissing('files', 'chunk_count INTEGER');
addColumnIfMissing('files', 'logical_size INTEGER');
addColumnIfMissing('files', 'chunk_sizes_json TEXT');
addColumnIfMissing('files', 'storage_object_id TEXT');
addColumnIfMissing("files", "listing_category TEXT NOT NULL DEFAULT 'other'");
addColumnIfMissing('files', 'inside_folder INTEGER');
addColumnIfMissing('uploads', 'encryption_version INTEGER NOT NULL DEFAULT 0');
addColumnIfMissing('uploads', 'encrypted_metadata TEXT');
addColumnIfMissing('uploads', 'encrypted_metadata_iv TEXT');
addColumnIfMissing('uploads', 'logical_size INTEGER');
addColumnIfMissing('uploads', 'chunk_sizes_json TEXT');
addColumnIfMissing('uploads', 'received_size INTEGER NOT NULL DEFAULT 0');
addColumnIfMissing('uploads', 'storage_object_id TEXT');
addColumnIfMissing("uploads", "listing_category TEXT NOT NULL DEFAULT 'other'");
addColumnIfMissing('uploads', 'inside_folder INTEGER');
addColumnIfMissing('encrypted_folders', 'is_root INTEGER');
db.exec('CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique ON users(email COLLATE NOCASE) WHERE email IS NOT NULL');
db.exec('CREATE UNIQUE INDEX IF NOT EXISTS files_upload_unique ON files(user_id, upload_id) WHERE upload_id IS NOT NULL');
db.exec('CREATE INDEX IF NOT EXISTS payment_orders_user_type_created ON payment_orders(user_id, order_type, created_at DESC)');
db.exec('CREATE INDEX IF NOT EXISTS storage_addons_user_expiry ON storage_addons(user_id, expires_at DESC, id DESC)');
db.exec('CREATE INDEX IF NOT EXISTS users_storage_overage_since ON users(storage_overage_since) WHERE storage_overage_since IS NOT NULL');
db.prepare('UPDATE users SET quota_bytes = ? WHERE quota_bytes < ?').run(USER_QUOTA, USER_QUOTA);
// Encrypted objects must never retain user-readable names or media types in
// database rows. This startup migration also scrubs rows created by older
// clients that wrote a display name after decrypting in the browser.
db.prepare(`UPDATE files SET original_name = 'Encrypted file', mime_type = 'application/octet-stream'
  WHERE encryption_version = ? AND (original_name != 'Encrypted file' OR mime_type != 'application/octet-stream')`)
  .run(ENCRYPTION_VERSION);
db.prepare(`UPDATE uploads SET original_name = 'Encrypted file', mime_type = 'application/octet-stream'
  WHERE encryption_version = ? AND (original_name != 'Encrypted file' OR mime_type != 'application/octet-stream')`)
  .run(ENCRYPTION_VERSION);

function escapeSiteHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;'
  }[character]));
}

function safeSiteHref(value) {
  const href = String(value || '').trim();
  return href.startsWith('/') || href.startsWith('#') || href.startsWith('mailto:')
    || /^https:\/\//i.test(href);
}

function sanitizeSiteHtml(value) {
  let html = String(value || '').slice(0, 500_000);
  html = html.replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<(script|style|iframe|object|embed|svg|math|template|form|head|body)[^>]*>[\s\S]*?<\/\1>/gi, '');
  const allowed = new Set(['p', 'br', 'strong', 'em', 'b', 'i', 'u', 'h2', 'h3', 'h4', 'ul', 'ol', 'li', 'blockquote', 'table', 'thead', 'tbody', 'tr', 'th', 'td', 'div', 'span', 'a']);
  const allowedClasses = new Set(['notice', 'warning']);
  html = html.replace(/<([a-z][a-z0-9]*)\b([^>]*)>/gi, (full, rawTag, rawAttrs) => {
    const tag = String(rawTag).toLowerCase();
    if (!allowed.has(tag)) return '';
    const classMatch = String(rawAttrs).match(/\bclass\s*=\s*(["'])(.*?)\1/i);
    const classes = classMatch
      ? classMatch[2].split(/\s+/).filter(className => allowedClasses.has(className)).join(' ')
      : '';
    const classAttr = classes ? ` class="${classes}"` : '';
    if (tag === 'a') {
      const match = String(rawAttrs).match(/\bhref\s*=\s*(["'])(.*?)\1/i);
      return match && safeSiteHref(match[2])
        ? `<a${classAttr} href="${escapeSiteHtml(match[2])}" rel="noreferrer noopener">`
        : `<a${classAttr}>`;
    }
    if (tag === 'h2' || tag === 'h3' || tag === 'h4') {
      const id = String(rawAttrs).match(/\bid\s*=\s*(["'])([a-zA-Z0-9_-]{1,80})\1/i);
      return id ? `<${tag}${classAttr} id="${id[2]}">` : `<${tag}${classAttr}>`;
    }
    return `<${tag}${classAttr}>`;
  });
  return html.replace(/<\/([a-z][a-z0-9]*)\s*>/gi, (full, rawTag) => {
    const tag = String(rawTag).toLowerCase();
    return allowed.has(tag) ? `</${tag}>` : '';
  });
}

function seedSiteContent(fileName) {
  const source = fs.readFileSync(path.join(process.cwd(), 'public', fileName), 'utf8');
  const main = source.match(/<main\b[^>]*>([\s\S]*?)<\/main>/i)?.[1] || '';
  const pick = pattern => main.match(pattern)?.[1]?.trim() || '';
  const bodyHtml = main
    .replace(/<p\b[^>]*class=["']eyebrow["'][^>]*>[\s\S]*?<\/p>/i, '')
    .replace(/<h1\b[^>]*>[\s\S]*?<\/h1>/i, '')
    .replace(/<p\b[^>]*class=["']intro["'][^>]*>[\s\S]*?<\/p>/i, '')
    .replace(/<p\b[^>]*class=["']meta["'][^>]*>[\s\S]*?<\/p>/i, '')
    .replace(/<nav\b[^>]*>[\s\S]*?<\/nav>/i, '')
    .trim();
  return {
    title: pick(/<h1\b[^>]*>([\s\S]*?)<\/h1>/i).replace(/<[^>]+>/g, '').trim(),
    intro: pick(/<p\b[^>]*class=["']intro["'][^>]*>([\s\S]*?)<\/p>/i).replace(/<[^>]+>/g, '').trim(),
    meta: pick(/<p\b[^>]*class=["']meta["'][^>]*>([\s\S]*?)<\/p>/i).replace(/<[^>]+>/g, '').trim(),
    bodyHtml: sanitizeSiteHtml(bodyHtml),
    enabled: 1
  };
}

function restoreLegacyNoticeClasses(bodyHtml, sourceHtml) {
  let restored = String(bodyHtml || '');
  for (const match of String(sourceHtml || '').matchAll(/<div class="(notice(?: warning)?)">[\s\S]*?<strong>([\s\S]*?)<\/strong>/gi)) {
    const [, classes, strongText] = match;
    const marker = `<div><strong>${strongText}</strong>`;
    if (restored.includes(marker)) restored = restored.replace(marker, `<div class="${classes}"><strong>${strongText}</strong>`);
  }
  return restored;
}

for (const [contentKey, definition] of SITE_CONTENT_DEFINITIONS) {
  if (db.prepare('SELECT 1 FROM site_content WHERE content_key = ?').get(contentKey)) continue;
  const seed = definition.fileName
    ? seedSiteContent(definition.fileName)
    : { title: definition.label, intro: '', meta: '', bodyHtml: '', enabled: 0 };
  db.prepare(`INSERT INTO site_content(content_key, title, intro, meta, body_html, enabled, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)`).run(contentKey, seed.title, seed.intro, seed.meta, seed.bodyHtml, seed.enabled, Date.now());
}
for (const [contentKey, definition] of SITE_CONTENT_DEFINITIONS) {
  if (!definition.fileName) continue;
  const current = db.prepare('SELECT body_html FROM site_content WHERE content_key = ?').get(contentKey);
  const source = seedSiteContent(definition.fileName).bodyHtml;
  const restoredBody = restoreLegacyNoticeClasses(current?.body_html, source);
  if (current && restoredBody !== current.body_html) {
    db.prepare('UPDATE site_content SET body_html = ? WHERE content_key = ?').run(restoredBody, contentKey);
  }
}

const q = {
  userByName: db.prepare('SELECT * FROM users WHERE username = ?'),
  userByEmail: db.prepare('SELECT * FROM users WHERE email = ? COLLATE NOCASE'),
  userById: db.prepare('SELECT * FROM users WHERE id = ?'),
  userBySession: db.prepare(`SELECT users.* FROM sessions JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ? AND sessions.expires_at > ?
      AND NOT EXISTS (SELECT 1 FROM account_deletions WHERE user_id = users.id AND status = 'scheduled')`),
  insertSession: db.prepare('INSERT INTO sessions(token_hash, user_id, expires_at) VALUES (?, ?, ?)'),
  deleteSession: db.prepare('DELETE FROM sessions WHERE token_hash = ?'),
  deleteUserSessions: db.prepare('DELETE FROM sessions WHERE user_id = ?'),
  listFiles: db.prepare(`SELECT id, upload_id,
    CASE WHEN encryption_version = ${ENCRYPTION_VERSION} THEN NULL ELSE original_name END AS original_name,
    CASE WHEN encryption_version = ${ENCRYPTION_VERSION} THEN NULL ELSE mime_type END AS mime_type,
    size, logical_size, chunk_sizes_json, created_at,
    encryption_version, encrypted_metadata, encrypted_metadata_iv, chunk_size, chunk_count,
    listing_category, inside_folder,
    CASE WHEN encryption_version = ${ENCRYPTION_VERSION} AND logical_size IS NOT NULL
      THEN logical_size
      WHEN encryption_version = ${ENCRYPTION_VERSION} AND chunk_count > 0
      THEN MAX(0, size - chunk_count * ${GCM_TAG_BYTES}) ELSE size END AS plain_size
    FROM files WHERE user_id = ? ORDER BY created_at DESC`),
  // Quotas and the UI count logical original bytes. Physical ciphertext size is
  // tracked separately because compressed chunks are variable length.
  usage: db.prepare(`SELECT COALESCE(SUM(CASE WHEN encryption_version = ${ENCRYPTION_VERSION}
    AND logical_size IS NOT NULL THEN logical_size
    WHEN encryption_version = ${ENCRYPTION_VERSION} AND chunk_count > 0 THEN MAX(0, size - chunk_count * ${GCM_TAG_BYTES}) ELSE size END), 0) AS bytes
    FROM files WHERE user_id = ?`),
  reserved: db.prepare(`SELECT COALESCE(SUM(CASE WHEN encryption_version = ${ENCRYPTION_VERSION}
    AND logical_size IS NOT NULL THEN logical_size
    WHEN encryption_version = ${ENCRYPTION_VERSION} AND chunk_count > 0 THEN MAX(0, size - chunk_count * ${GCM_TAG_BYTES}) ELSE size END), 0) AS bytes
    FROM uploads WHERE user_id = ?`),
  listUploads: db.prepare(`SELECT id,
    CASE WHEN encryption_version = ${ENCRYPTION_VERSION} THEN NULL ELSE original_name END AS original_name,
    size, logical_size, chunk_sizes_json, received_size, chunk_size, chunk_count, created_at,
    encryption_version, encrypted_metadata, encrypted_metadata_iv,
    CASE WHEN encryption_version = ${ENCRYPTION_VERSION} AND logical_size IS NOT NULL
      THEN logical_size
      WHEN encryption_version = ${ENCRYPTION_VERSION} AND chunk_count > 0
      THEN MAX(0, size - chunk_count * ${GCM_TAG_BYTES}) ELSE size END AS plain_size
    FROM uploads WHERE user_id = ? ORDER BY created_at DESC`),
  upload: db.prepare('SELECT * FROM uploads WHERE id = ? AND user_id = ?'),
  touchUpload: db.prepare('UPDATE uploads SET created_at = ? WHERE id = ? AND user_id = ?'),
  fileByUpload: db.prepare('SELECT * FROM files WHERE upload_id = ? AND user_id = ?'),
  file: db.prepare('SELECT * FROM files WHERE id = ? AND user_id = ?'),
  updateFileMetadata: db.prepare(`UPDATE files
    SET encrypted_metadata = ?, encrypted_metadata_iv = ?,
      original_name = 'Encrypted file', mime_type = 'application/octet-stream'
    WHERE id = ? AND user_id = ? AND encryption_version = ${ENCRYPTION_VERSION}`),
  updateFileListingHint: db.prepare(`UPDATE files SET listing_category = ?, inside_folder = ?
    WHERE id = ? AND user_id = ? AND encryption_version = ${ENCRYPTION_VERSION}`),
  listEncryptedFolders: db.prepare(`SELECT id, encrypted_metadata, encrypted_metadata_iv, is_root, created_at, updated_at
    FROM encrypted_folders WHERE user_id = ? ORDER BY created_at ASC, id ASC`),
  encryptedFolder: db.prepare('SELECT * FROM encrypted_folders WHERE id = ? AND user_id = ?'),
  insertEncryptedFolder: db.prepare(`INSERT INTO encrypted_folders(
    id, user_id, encrypted_metadata, encrypted_metadata_iv, is_root, created_at, updated_at
  ) VALUES (?, ?, ?, ?, ?, ?, ?)`),
  updateEncryptedFolderHint: db.prepare('UPDATE encrypted_folders SET is_root = ?, updated_at = ? WHERE id = ? AND user_id = ?'),
  updateEncryptedFolderMetadata: db.prepare(`UPDATE encrypted_folders
    SET encrypted_metadata = ?, encrypted_metadata_iv = ?, is_root = ?, updated_at = ?
    WHERE id = ? AND user_id = ?`),
  deleteEncryptedFolder: db.prepare('DELETE FROM encrypted_folders WHERE id = ? AND user_id = ?'),
  listUserUploads: db.prepare('SELECT * FROM uploads WHERE user_id = ?'),
  scheduledDeletion: db.prepare(`SELECT * FROM account_deletions
    WHERE user_id = ? AND status = 'scheduled' ORDER BY requested_at DESC LIMIT 1`),
  deletionByToken: db.prepare(`SELECT * FROM account_deletions
    WHERE cancellation_token_hash = ? AND status = 'scheduled' LIMIT 1`),
  dueDeletions: db.prepare(`SELECT * FROM account_deletions
    WHERE status = 'scheduled' AND scheduled_for <= ? ORDER BY scheduled_for ASC LIMIT 25`),
  pendingDeletionNotices: db.prepare(`SELECT * FROM account_deletions
    WHERE status = 'erased_pending_notification' ORDER BY completed_at ASC LIMIT 25`),
  passwordReset: db.prepare(`SELECT password_resets.*, users.id AS account_id
    FROM password_resets JOIN users ON users.id = password_resets.user_id
    WHERE password_resets.token_hash = ? AND password_resets.expires_at > ?`),
  deleteUserPasswordResets: db.prepare('DELETE FROM password_resets WHERE user_id = ?'),
  deleteExpiredPasswordResets: db.prepare('DELETE FROM password_resets WHERE expires_at <= ?'),
  listActiveVaultPasskeys: db.prepare(`SELECT credential_id, attachment, device_type, backed_up,
    wrapper_salt, wrapper_iv, wrapped_key, created_at, last_used_at
    FROM vault_passkeys WHERE user_id = ? AND state = 'active' ORDER BY created_at ASC`),
  listActiveVaultPasskeyRecords: db.prepare(`SELECT * FROM vault_passkeys
    WHERE user_id = ? AND state = 'active' ORDER BY created_at ASC`),
  listVaultPasskeysForRegistration: db.prepare(`SELECT credential_id, transports
    FROM vault_passkeys WHERE user_id = ?`),
  pendingVaultPasskey: db.prepare(`SELECT * FROM vault_passkeys
    WHERE credential_id = ? AND user_id = ? AND state = 'pending'`),
  activeVaultPasskey: db.prepare(`SELECT * FROM vault_passkeys
    WHERE credential_id = ? AND user_id = ? AND state = 'active'`),
  activeVaultPasskeyByCredential: db.prepare(`SELECT * FROM vault_passkeys
    WHERE credential_id = ? AND state = 'active'`),
  insertPendingVaultPasskey: db.prepare(`INSERT INTO vault_passkeys(
    credential_id, user_id, public_key, counter, transports, attachment, device_type, backed_up,
    state, created_at
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)`),
  activateVaultPasskey: db.prepare(`UPDATE vault_passkeys SET wrapper_salt = ?, wrapper_iv = ?,
    wrapped_key = ?, counter = ?, device_type = ?, backed_up = ?, state = 'active',
    activated_at = ?, last_used_at = ? WHERE credential_id = ? AND user_id = ? AND state = 'pending'`),
  updateVaultPasskeyUse: db.prepare(`UPDATE vault_passkeys SET counter = ?, device_type = ?,
    backed_up = ?, last_used_at = ? WHERE credential_id = ? AND user_id = ? AND state = 'active'`),
  deleteVaultPasskey: db.prepare('DELETE FROM vault_passkeys WHERE credential_id = ? AND user_id = ?'),
  clearVaultRecovery: db.prepare(`UPDATE users SET vault_recovery_salt = NULL, vault_recovery_iv = NULL,
    vault_recovery_wrapped_key = NULL, vault_recovery_kdf_iterations = NULL WHERE id = ?`),
  deleteStalePendingVaultPasskeys: db.prepare(`DELETE FROM vault_passkeys
    WHERE state = 'pending' AND created_at <= ?`),
  insertVaultPasskeyChallenge: db.prepare(`INSERT INTO vault_passkey_challenges(
    id, user_id, session_hash, purpose, challenge, credential_id, expires_at, created_at
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
  vaultPasskeyChallenge: db.prepare(`SELECT * FROM vault_passkey_challenges
    WHERE id = ? AND user_id = ? AND session_hash = ? AND purpose = ? AND expires_at > ?`),
  deleteVaultPasskeyChallenge: db.prepare('DELETE FROM vault_passkey_challenges WHERE id = ?'),
  deleteExpiredVaultPasskeyChallenges: db.prepare('DELETE FROM vault_passkey_challenges WHERE expires_at <= ?'),
  insertVaultRecoveryResetProof: db.prepare(`INSERT INTO vault_recovery_reset_proofs(
    token_hash, user_id, session_hash, credential_id, expires_at, created_at
  ) VALUES (?, ?, ?, ?, ?, ?)`),
  vaultRecoveryResetProof: db.prepare(`SELECT * FROM vault_recovery_reset_proofs
    WHERE token_hash = ? AND user_id = ? AND session_hash = ? AND expires_at > ?`),
  deleteVaultRecoveryResetProof: db.prepare('DELETE FROM vault_recovery_reset_proofs WHERE token_hash = ?'),
  deleteExpiredVaultRecoveryResetProofs: db.prepare('DELETE FROM vault_recovery_reset_proofs WHERE expires_at <= ?'),
  insertPasskeyActionChallenge: db.prepare(`INSERT INTO passkey_action_challenges(
    id, user_id, session_hash, purpose, challenge, expires_at, created_at
  ) VALUES (?, ?, ?, ?, ?, ?, ?)`),
  passkeyActionChallenge: db.prepare(`SELECT * FROM passkey_action_challenges
    WHERE id = ? AND user_id = ? AND session_hash = ? AND purpose = ? AND expires_at > ?`),
  deletePasskeyActionChallenge: db.prepare('DELETE FROM passkey_action_challenges WHERE id = ?'),
  deleteExpiredPasskeyActionChallenges: db.prepare('DELETE FROM passkey_action_challenges WHERE expires_at <= ?'),
  insertPasskeyActionProof: db.prepare(`INSERT INTO passkey_action_proofs(
    token_hash, user_id, session_hash, credential_id, purpose, expires_at, created_at
  ) VALUES (?, ?, ?, ?, ?, ?, ?)`),
  passkeyActionProof: db.prepare(`SELECT * FROM passkey_action_proofs
    WHERE token_hash = ? AND user_id = ? AND session_hash = ? AND purpose = ? AND expires_at > ?`),
  deletePasskeyActionProof: db.prepare('DELETE FROM passkey_action_proofs WHERE token_hash = ?'),
  deleteExpiredPasskeyActionProofs: db.prepare('DELETE FROM passkey_action_proofs WHERE expires_at <= ?'),
  insertPasskeyLoginChallenge: db.prepare(`INSERT INTO passkey_login_challenges(
    id, challenge, expires_at, created_at
  ) VALUES (?, ?, ?, ?)`),
  passkeyLoginChallenge: db.prepare(`SELECT * FROM passkey_login_challenges
    WHERE id = ? AND expires_at > ?`),
  deletePasskeyLoginChallenge: db.prepare('DELETE FROM passkey_login_challenges WHERE id = ?'),
  deleteExpiredPasskeyLoginChallenges: db.prepare('DELETE FROM passkey_login_challenges WHERE expires_at <= ?')
};

const cancelledUploads = new Map();
const completingUploads = new Map();
const finalizingAccountDeletions = new Set();

function token() {
  return crypto.randomBytes(32).toString('base64url');
}

function hashToken(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function cookies(req) {
  return Object.fromEntries((req.headers.cookie || '').split(';').map(v => v.trim().split('=').map(decodeURIComponent)).filter(v => v.length === 2));
}

function cleanName(name) {
  const cleaned = String(name || '').replace(/[\u0000-\u001f\u007f]/g, '').replace(/[\\/]/g, '_').trim();
  return cleaned.slice(0, 240) || 'unnamed-file';
}

function jsonError(res, status, message) {
  return res.status(status).json({ error: message });
}

function setSession(res, userId) {
  const raw = token();
  q.insertSession.run(hashToken(raw), userId, Date.now() + SESSION_TTL);
  res.cookie('share_session', raw, {
    httpOnly: true,
    secure: PUBLIC_URL.startsWith('https://'),
    sameSite: 'strict',
    maxAge: SESSION_TTL,
    path: '/'
  });
}

function setAdminSession(res) {
  const raw = token();
  db.prepare('INSERT INTO admin_sessions(token_hash, expires_at, created_at) VALUES (?, ?, ?)')
    .run(hashToken(raw), Date.now() + ADMIN_SESSION_TTL, Date.now());
  res.cookie('share_admin_session', raw, {
    httpOnly: true, secure: PUBLIC_URL.startsWith('https://'), sameSite: 'strict',
    maxAge: ADMIN_SESSION_TTL, path: '/'
  });
}

function clearAdminSession(req, res) {
  const raw = cookies(req).share_admin_session;
  if (raw) db.prepare('DELETE FROM admin_sessions WHERE token_hash = ?').run(hashToken(raw));
  res.clearCookie('share_admin_session', { path: '/', sameSite: 'strict', secure: PUBLIC_URL.startsWith('https://') });
}

function requireAdmin(req, res, next) {
  const raw = cookies(req).share_admin_session;
  if (!raw || !ADMIN_PASSWORD) return jsonError(res, 401, '请使用独立管理员账户登录');
  const session = db.prepare('SELECT 1 FROM admin_sessions WHERE token_hash = ? AND expires_at > ?')
    .get(hashToken(raw), Date.now());
  if (!session) return jsonError(res, 401, '管理员会话已过期，请重新登录');
  next();
}

function auditAdmin(action, targetUserId, details) {
  db.prepare('INSERT INTO admin_audit_logs(action, target_user_id, details, created_at) VALUES (?, ?, ?, ?)')
    .run(action, targetUserId, JSON.stringify(details), Date.now());
}

function cleanupAdminAuditLogs() {
  return db.prepare('DELETE FROM admin_audit_logs WHERE created_at < ?')
    .run(Date.now() - ADMIN_AUDIT_RETENTION).changes;
}

function createAdminPasskeyChallenge(purpose, challenge) {
  const id = crypto.randomUUID(); const now = Date.now();
  db.prepare('INSERT INTO admin_passkey_challenges(id, purpose, challenge, expires_at, created_at) VALUES (?, ?, ?, ?, ?)')
    .run(id, purpose, challenge, now + PASSKEY_CHALLENGE_TTL, now);
  return id;
}

function consumeAdminPasskeyChallenge(id, purpose) {
  if (!/^[0-9a-f-]{36}$/i.test(String(id || ''))) return null;
  const row = db.prepare('SELECT * FROM admin_passkey_challenges WHERE id = ? AND purpose = ? AND expires_at > ?')
    .get(id, purpose, Date.now());
  if (row) db.prepare('DELETE FROM admin_passkey_challenges WHERE id = ?').run(row.id);
  return row;
}

function refreshUserEntitlements(userId, now = Date.now()) {
  let subscription = db.prepare('SELECT plan_id, quota_bytes, expires_at FROM subscriptions WHERE user_id = ?').get(userId);
  let addons = db.prepare(`SELECT id, addon_id, quota_bytes, expires_at, created_at
    FROM storage_addons WHERE user_id = ? ORDER BY created_at ASC, id ASC`).all(userId);
  const subscriptionExpired = Boolean(subscription && Number(subscription.expires_at) <= now);
  const expiredAddons = addons.filter(addon => Number(addon.expires_at) <= now);
  const expiredAddonIds = expiredAddons.map(addon => addon.id);
  const expiredAt = [subscriptionExpired ? Number(subscription.expires_at) : 0, ...expiredAddons.map(addon => Number(addon.expires_at))]
    .filter(Boolean);
  let changed = false;
  if (subscriptionExpired || expiredAddonIds.length) db.transaction(() => {
    if (subscriptionExpired) db.prepare('DELETE FROM subscriptions WHERE user_id = ?').run(userId);
    if (expiredAddonIds.length) {
      const placeholders = expiredAddonIds.map(() => '?').join(',');
      db.prepare(`DELETE FROM storage_addons WHERE id IN (${placeholders})`).run(...expiredAddonIds);
    }
    subscription = subscriptionExpired ? null : subscription;
    addons = addons.filter(addon => Number(addon.expires_at) > now);
    const addonQuota = addons.reduce((sum, addon) => sum + Number(addon.quota_bytes), 0);
    const effectiveQuota = subscription
      ? Number(subscription.quota_bytes) + addonQuota
      : USER_QUOTA;
    db.prepare('UPDATE users SET quota_bytes = ? WHERE id = ?').run(effectiveQuota, userId);
    changed = true;
  })();
  const user = q.userById.get(userId);
  const used = Number(q.usage.get(userId).bytes);
  const overQuota = used > Number(user.quota_bytes);
  let overageSince = Number(user.storage_overage_since) || null;
  if (overQuota && !overageSince && expiredAt.length) {
    // When several entitlements expired while the account was inactive, use
    // the latest expiry as the most generous deterministic start time.
    overageSince = Math.max(...expiredAt);
    db.prepare('UPDATE users SET storage_overage_since = ? WHERE id = ?').run(overageSince, userId);
    changed = true;
  } else if (!overQuota && overageSince) {
    db.prepare('UPDATE users SET storage_overage_since = NULL WHERE id = ?').run(userId);
    overageSince = null;
    changed = true;
  }
  return {
    subscription,
    addons,
    changed,
    used,
    overageSince,
    overageDeadline: overageSince ? overageSince + PAID_STORAGE_GRACE_MS : null
  };
}

function requireAuth(req, res, next) {
  const raw = cookies(req).share_session;
  let user = raw && q.userBySession.get(hashToken(raw), Date.now());
  if (!user) return jsonError(res, 401, '请先登录');
  if (refreshUserEntitlements(user.id).changed) user = q.userById.get(user.id);
  req.user = user;
  req.sessionToken = raw;
  next();
}

function originGuard(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const origin = req.get('origin');
  if (origin && origin !== PUBLIC_URL) return jsonError(res, 403, '请求来源无效');
  next();
}

function validUsername(value) {
  return /^[a-zA-Z0-9_]{3,32}$/.test(value);
}

function normalizeEmail(value) {
  const email = String(value || '').trim().toLowerCase();
  return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ? email : '';
}

function validCode(value) {
  return /^(?=.*[A-Z])(?=.*\d)[A-Z0-9]{6}$/.test(String(value || '').trim().toUpperCase());
}

function validUploadId(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function base64url(value, minimumLength, maximumLength) {
  const text = String(value || '');
  return /^[A-Za-z0-9_-]+$/.test(text) && text.length >= minimumLength && text.length <= maximumLength ? text : '';
}

function secureExternalUrl(value) {
  try {
    const parsed = new URL(String(value || ''));
    return parsed.protocol === 'https:' ? parsed.href : '';
  } catch {
    return '';
  }
}

function vaultConfig(value) {
  if (!value || typeof value !== 'object') return null;
  const version = Number(value.version);
  const iterations = Number(value.iterations);
  const salt = base64url(value.salt, 22, 86);
  const iv = base64url(value.iv, 16, 24);
  const wrappedKey = base64url(value.wrappedKey, 43, 160);
  if (version !== ENCRYPTION_VERSION || iterations !== VAULT_KDF_ITERATIONS || !salt || !iv || !wrappedKey) return null;
  return { version, iterations, salt, iv, wrappedKey };
}

function vaultRecoveryConfig(value) {
  if (!value || typeof value !== 'object') return null;
  const iterations = Number(value.iterations);
  const salt = base64url(value.salt, 22, 86);
  const iv = base64url(value.iv, 16, 24);
  const wrappedKey = base64url(value.wrappedKey, 43, 160);
  if (iterations !== VAULT_KDF_ITERATIONS || !salt || !iv || !wrappedKey) return null;
  return { iterations, salt, iv, wrappedKey };
}

function vaultPasskeyConfig(value) {
  if (!value || typeof value !== 'object') return null;
  const version = Number(value.version);
  const salt = base64url(value.salt, 22, 86);
  const iv = base64url(value.iv, 16, 24);
  const wrappedKey = base64url(value.wrappedKey, 43, 160);
  if (version !== ENCRYPTION_VERSION || !salt || !iv || !wrappedKey) return null;
  return { version, salt, iv, wrappedKey };
}

function passkeyPreference(value) {
  const preference = String(value || 'any');
  if (preference === 'platform') return 'localDevice';
  if (preference === 'cross-platform') return 'securityKey';
  return 'any';
}

function passkeyTransports(value) {
  const allowed = new Set(['ble', 'cable', 'hybrid', 'internal', 'nfc', 'smart-card', 'usb']);
  const transports = Array.isArray(value) ? value.filter(item => allowed.has(item)) : [];
  return [...new Set(transports)].slice(0, 8);
}

function storedPasskeyTransports(value) {
  try {
    return passkeyTransports(JSON.parse(value || '[]'));
  } catch {
    return [];
  }
}

function passkeyClientSummary(row) {
  return {
    credentialId: row.credential_id,
    attachment: row.attachment,
    deviceType: row.device_type,
    backedUp: Boolean(row.backed_up),
    createdAt: row.created_at,
    lastUsedAt: row.last_used_at,
    wrapping: {
      version: ENCRYPTION_VERSION,
      salt: row.wrapper_salt,
      iv: row.wrapper_iv,
      wrappedKey: row.wrapped_key
    }
  };
}

function webauthnCredential(row) {
  return {
    id: row.credential_id,
    publicKey: new Uint8Array(Buffer.from(row.public_key, 'base64url')),
    counter: Number(row.counter),
    transports: storedPasskeyTransports(row.transports)
  };
}

function createVaultPasskeyChallenge(req, purpose, challenge, credentialId = null) {
  const id = crypto.randomUUID();
  const now = Date.now();
  q.insertVaultPasskeyChallenge.run(
    id,
    req.user.id,
    hashToken(req.sessionToken),
    purpose,
    challenge,
    credentialId,
    now + PASSKEY_CHALLENGE_TTL,
    now
  );
  return id;
}

function consumeVaultPasskeyChallenge(req, id, purpose) {
  if (!/^[0-9a-f-]{36}$/i.test(String(id || ''))) return null;
  const challenge = q.vaultPasskeyChallenge.get(
    id,
    req.user.id,
    hashToken(req.sessionToken),
    purpose,
    Date.now()
  );
  if (challenge) q.deleteVaultPasskeyChallenge.run(challenge.id);
  return challenge;
}

function createPasskeyLoginChallenge(challenge) {
  const id = crypto.randomUUID();
  const now = Date.now();
  q.insertPasskeyLoginChallenge.run(id, challenge, now + PASSKEY_CHALLENGE_TTL, now);
  return id;
}

function consumePasskeyLoginChallenge(id) {
  if (!/^[0-9a-f-]{36}$/i.test(String(id || ''))) return null;
  const challenge = q.passkeyLoginChallenge.get(id, Date.now());
  if (challenge) q.deletePasskeyLoginChallenge.run(challenge.id);
  return challenge;
}

function createVaultRecoveryResetProof(req, credentialId) {
  const raw = token();
  const now = Date.now();
  q.insertVaultRecoveryResetProof.run(
    hashToken(raw),
    req.user.id,
    hashToken(req.sessionToken),
    credentialId,
    now + VAULT_RECOVERY_RESET_PROOF_TTL,
    now
  );
  return raw;
}

function consumeVaultRecoveryResetProof(req, value) {
  const raw = base64url(value, 32, 128);
  if (!raw) return null;
  const tokenHash = hashToken(raw);
  const proof = q.vaultRecoveryResetProof.get(
    tokenHash,
    req.user.id,
    hashToken(req.sessionToken),
    Date.now()
  );
  if (proof) q.deleteVaultRecoveryResetProof.run(tokenHash);
  return proof;
}

const PASSKEY_ACTIONS = new Set(['account-deletion', 'passkey-management']);

function passkeyAction(value) {
  const action = String(value || '');
  return PASSKEY_ACTIONS.has(action) ? action : null;
}

function createPasskeyActionChallenge(req, purpose, challenge) {
  const id = crypto.randomUUID();
  const now = Date.now();
  q.insertPasskeyActionChallenge.run(
    id,
    req.user.id,
    hashToken(req.sessionToken),
    purpose,
    challenge,
    now + PASSKEY_CHALLENGE_TTL,
    now
  );
  return id;
}

function consumePasskeyActionChallenge(req, id, purpose) {
  if (!/^[0-9a-f-]{36}$/i.test(String(id || ''))) return null;
  const challenge = q.passkeyActionChallenge.get(
    id,
    req.user.id,
    hashToken(req.sessionToken),
    purpose,
    Date.now()
  );
  if (challenge) q.deletePasskeyActionChallenge.run(challenge.id);
  return challenge;
}

function createPasskeyActionProof(req, credentialId, purpose) {
  const raw = token();
  const now = Date.now();
  q.insertPasskeyActionProof.run(
    hashToken(raw),
    req.user.id,
    hashToken(req.sessionToken),
    credentialId,
    purpose,
    now + VAULT_RECOVERY_RESET_PROOF_TTL,
    now
  );
  return raw;
}

function consumePasskeyActionProof(req, purpose, value) {
  const raw = base64url(value, 32, 128);
  if (!raw) return null;
  const tokenHash = hashToken(raw);
  const proof = q.passkeyActionProof.get(
    tokenHash,
    req.user.id,
    hashToken(req.sessionToken),
    purpose,
    Date.now()
  );
  if (proof) q.deletePasskeyActionProof.run(tokenHash);
  return proof;
}

function passkeyAuthenticationExtensions() {
  // The PRF input is public and stable. Only the authenticator can produce the
  // credential-specific output that is used in the browser to wrap the vault key.
  return { prf: { eval: { first: VAULT_PASSKEY_PRF_INPUT } } };
}

function uploadEncryption(value) {
  if (!value || typeof value !== 'object') return null;
  const version = Number(value.version);
  const metadata = base64url(value.metadata, 24, ENCRYPTED_METADATA_MAX_LENGTH);
  const metadataIv = base64url(value.metadataIv, 16, 24);
  if (version !== ENCRYPTION_VERSION || !metadata || !metadataIv) return null;
  return { version, metadata, metadataIv };
}

function listingHint(value) {
  const category = LISTING_CATEGORIES.has(String(value?.category || ''))
    ? String(value.category)
    : 'other';
  return {
    category,
    insideFolder: value?.insideFolder === true ? 1 : 0
  };
}

function uploadKey(userId, uploadId) {
  return `${userId}:${uploadId}`;
}

function markUploadCancelled(userId, uploadId) {
  cancelledUploads.set(uploadKey(userId, uploadId), Date.now() + CANCELLATION_TTL);
}

function isUploadCancelled(userId, uploadId) {
  return cancelledUploads.has(uploadKey(userId, uploadId));
}

function uploadCancelledError() {
  const error = new Error('UPLOAD_CANCELLED');
  error.code = 'UPLOAD_CANCELLED';
  return error;
}

async function mailRequest(action, email, code, ip) {
  if (!MAIL_API_URL || !MAIL_API_TOKEN) return { ok: false, status: 503, error: '邮箱验证码服务尚未配置' };
  try {
    const response = await fetch(MAIL_API_URL, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${MAIL_API_TOKEN}`,
        'Content-Type': 'application/json',
        'X-Forwarded-For': ip
      },
      body: JSON.stringify({ to: email, scope: MAIL_SCOPE, action, code }),
      signal: AbortSignal.timeout(12_000)
    });
    const data = await response.json().catch(() => ({}));
    return { ok: response.ok, status: response.status, ...data };
  } catch {
    return { ok: false, status: 503, error: '邮箱验证码服务暂时不可用' };
  }
}

async function transactionalMailRequest({
  to,
  subject,
  text,
  actionUrl = '',
  actionLabel = '',
  template = '',
  templateData = null,
  idempotencyKey = ''
}) {
  if (!TRANSACTIONAL_MAIL_API_URL || !MAIL_API_TOKEN) {
    return { ok: false, status: 503, error: '账户通知邮件服务尚未配置' };
  }
  try {
    const response = await fetch(TRANSACTIONAL_MAIL_API_URL, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${MAIL_API_TOKEN}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        to, subject, text, actionUrl, actionLabel, template, templateData, idempotencyKey
      }),
      signal: AbortSignal.timeout(12_000)
    });
    const data = await response.json().catch(() => ({}));
    return { ok: response.ok, status: response.status, ...data };
  } catch {
    return { ok: false, status: 503, error: '账户通知邮件服务暂时不可用' };
  }
}

const membershipExpiryReminderService = createMembershipExpiryReminderService({
  db,
  sendMail: transactionalMailRequest,
  getUsage: userId => Number(q.usage.get(userId).bytes),
  publicUrl: PUBLIC_URL,
  freeQuotaBytes: USER_QUOTA
});

function formatUtcTime(timestamp) {
  return new Intl.DateTimeFormat('en-US', {
    timeZone: 'UTC',
    month: 'long',
    day: 'numeric',
    year: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    hour12: true,
    timeZoneName: 'short'
  }).format(new Date(timestamp));
}

function deletionScheduledMessage(deletion, cancellationToken) {
  const scheduledAt = formatUtcTime(deletion.scheduled_for);
  return {
    subject: 'Yuni Share · Account Deletion Scheduled',
    text: `This email confirms your request to delete your Yuni Share account.\n\nYour account has been signed out and locked. You selected a ${deletion.retention_days}-day recovery period. On ${scheduledAt}, Yuni Share will permanently erase your account record and the encrypted files stored for this account. This action cannot be undone once the scheduled date has passed.\n\nThe secure recovery link below is valid until ${scheduledAt}, which is the end of the recovery period you selected. It is a single-use link: if you use it to restore the account, the scheduled deletion is cancelled immediately and this link stops working. You do not need to know your previous login password to use the link. Keep this email private and do not forward the link; anyone who can access this email and link before it expires could restore the account.\n\nThe recovery period is the period you selected, not a claim that your erasure request has already been completed. Yuni Share does not keep a separate copy of your encrypted files for this deletion flow. Any limited retention that may be required by applicable law must be assessed separately and documented for that specific obligation.`,
    actionUrl: `${PUBLIC_URL}/recovery-account#cancel-deletion=${cancellationToken}`,
    actionLabel: 'Cancel Scheduled Deletion'
  };
}

function deletionCompletedMessage(deletion) {
  const completedAt = formatUtcTime(deletion.completed_at);
  return {
    subject: 'Yuni Share · Account Deletion Completed',
    text: `Your Yuni Share account deletion has been completed on ${completedAt}.\n\nThe account record, active sessions, upload sessions, and encrypted files associated with this account have been permanently erased. The deletion cannot be reversed.\n\nThis notification is sent only after the deletion process has completed. We will not keep the cancellation link or account credentials after this notification is delivered.`
  };
}

function passwordResetMessage(resetToken) {
  return {
    subject: 'Yuni Share · Reset Your Login Password',
    text: 'We received a request to reset your Yuni Share login password. Use the secure button below within 15 minutes to choose a new login password. This link can be used only once.\n\nResetting your login password does not change your separate encryption password and does not give Yuni Share access to encrypted files. If you did not request this change, you can safely ignore this email.',
    actionUrl: `${PUBLIC_URL}/#reset-login-password=${resetToken}`,
    actionLabel: 'Reset Login Password'
  };
}

function requestIp(req) {
  return String(req.get('cf-connecting-ip') || req.ip || 'unknown').slice(0, 80);
}

async function removeUpload(upload) {
  db.prepare('DELETE FROM uploads WHERE id = ?').run(upload.id);
  await fsp.rm(path.join(TEMP_ROOT, upload.id), { recursive: true, force: true });
  if (STORAGE_ENABLED && upload.storage_object_id) await storageRequest(`/internal/share/objects/${encodeURIComponent(upload.storage_object_id)}`, { method: 'DELETE' }).catch(() => {});
}

async function storageRequest(pathname, options = {}) {
  const response = await fetch(`${STORAGE_API_URL}${pathname}`, {
    ...options,
    headers: { Authorization: `Bearer ${STORAGE_API_TOKEN}`, ...(options.headers || {}) },
    duplex: options.body ? 'half' : undefined,
  });
  if (!response.ok) throw new Error((await response.json().catch(() => ({}))).error || `存储服务错误 (${response.status})`);
  return response;
}

async function storageUploadChunkSizes(upload) {
  const response = await storageRequest(`/internal/share/objects/${encodeURIComponent(upload.storage_object_id)}`);
  const state = await response.json();
  if (state.kind !== 'upload' || Number(state.chunkCount) !== Number(upload.chunk_count)) return null;
  const sizes = Array(Number(upload.chunk_count)).fill(null);
  for (const part of Array.isArray(state.parts) ? state.parts : []) {
    const index = Number(part.index);
    const size = Number(part.size);
    if (!Number.isInteger(index) || index < 0 || index >= sizes.length
      || sizes[index] !== null || part.pending === true || !Number.isSafeInteger(size) || size <= 0) return null;
    sizes[index] = size;
  }
  const received = sizes.reduce((sum, size) => sum + (Number(size) || 0), 0);
  if (!sizes.every((size) => Number.isSafeInteger(size) && size > 0)
    || received !== Number(state.received) || received > Number(upload.size)) return null;
  return sizes;
}

function plainStoredFileSize(file) {
  if (file.encryption_version === ENCRYPTION_VERSION && file.logical_size !== null
    && file.logical_size !== undefined && Number.isSafeInteger(Number(file.logical_size))) {
    return Math.max(0, Number(file.logical_size));
  }
  return file.encryption_version === ENCRYPTION_VERSION && Number(file.chunk_count) > 0
    ? Math.max(0, Number(file.size) - Number(file.chunk_count) * GCM_TAG_BYTES)
    : Number(file.size);
}

function parseChunkSizes(value, expectedCount = null) {
  if (!value) return null;
  let sizes;
  try { sizes = JSON.parse(String(value)); } catch { return null; }
  if (!Array.isArray(sizes) || (expectedCount !== null && sizes.length !== expectedCount)) return null;
  if (!sizes.every((size) => Number.isSafeInteger(size) && size > 0)) return null;
  return sizes;
}

function recordedUploadChunkSizes(upload) {
  if (!upload?.chunk_sizes_json) return null;
  let sizes;
  try { sizes = JSON.parse(String(upload.chunk_sizes_json)); } catch { return null; }
  if (!Array.isArray(sizes) || sizes.length !== Number(upload.chunk_count)) return null;
  return sizes;
}

function uploadChunkSizes(upload) {
  const sizes = recordedUploadChunkSizes(upload);
  if (sizes && sizes.every((size) => Number.isSafeInteger(size) && size > 0)) return sizes;
  if (!Number.isSafeInteger(Number(upload.size)) || !Number.isSafeInteger(Number(upload.chunk_size))
    || !Number.isInteger(Number(upload.chunk_count)) || Number(upload.chunk_count) < 1) return null;
  return Array.from({ length: Number(upload.chunk_count) }, (_, index) => (
    index === Number(upload.chunk_count) - 1
      ? Number(upload.size) - Number(upload.chunk_size) * index
      : Number(upload.chunk_size)
  ));
}

function recordUploadChunk(uploadId, userId, index, size) {
  return db.transaction(() => {
    const upload = db.prepare('SELECT * FROM uploads WHERE id = ? AND user_id = ?').get(uploadId, userId);
    if (!upload) return null;
    const sizes = parseChunkSizes(upload.chunk_sizes_json, Number(upload.chunk_count))
      || Array(Number(upload.chunk_count)).fill(null);
    if (sizes[index] !== null && sizes[index] !== undefined && sizes[index] !== size) {
      throw new Error('上传分片大小与已记录内容不一致');
    }
    sizes[index] = size;
    const received = sizes.reduce((sum, value) => sum + (Number(value) || 0), 0);
    db.prepare(`UPDATE uploads
      SET chunk_sizes_json = ?, received_size = ?, created_at = ?
      WHERE id = ? AND user_id = ?`).run(JSON.stringify(sizes), received, Date.now(), uploadId, userId);
    return { ...upload, chunk_sizes_json: JSON.stringify(sizes), received_size: received };
  })();
}

function fileChunkSizes(file) {
  const sizes = parseChunkSizes(file.chunk_sizes_json, Number(file.chunk_count));
  if (sizes && sizes.reduce((sum, value) => sum + value, 0) === Number(file.size)) return sizes;
  if (!Number.isSafeInteger(Number(file.size)) || !Number.isSafeInteger(Number(file.chunk_size))
    || !Number.isInteger(Number(file.chunk_count)) || Number(file.chunk_count) < 1) return null;
  const legacy = Array.from({ length: Number(file.chunk_count) }, (_, index) => (
    index === Number(file.chunk_count) - 1
      ? Number(file.size) - Number(file.chunk_size) * index
      : Number(file.chunk_size)
  ));
  return legacy.every((value) => value > 0) ? legacy : null;
}

async function removeStoredFile(file) {
  if (STORAGE_ENABLED && file.storage_object_id) {
    await storageRequest(`/internal/share/objects/${encodeURIComponent(file.storage_object_id)}`, { method: 'DELETE' });
  } else {
    await fsp.rm(path.join(FILE_ROOT, String(file.user_id), file.stored_name), { force: true });
  }
  db.prepare('DELETE FROM files WHERE id = ? AND user_id = ?').run(file.id, file.user_id);
}

async function cleanupExpiredPaidStorage(now = Date.now()) {
  const affectedUsers = db.prepare(`SELECT * FROM users
    WHERE storage_overage_since IS NOT NULL AND storage_overage_since + ? <= ?
    ORDER BY storage_overage_since ASC`).all(PAID_STORAGE_GRACE_MS, now);
  for (const user of affectedUsers) {
    refreshUserEntitlements(user.id, now);
    const current = q.userById.get(user.id);
    if (!current?.storage_overage_since || Number(current.storage_overage_since) + PAID_STORAGE_GRACE_MS > now) continue;
    let used = Number(q.usage.get(user.id).bytes);
    if (used <= Number(current.quota_bytes)) {
      db.prepare('UPDATE users SET storage_overage_since = NULL WHERE id = ?').run(user.id);
      continue;
    }
    // Files are indivisible encrypted objects. Delete newest complete files
    // first until usage no longer exceeds the restored free quota.
    const files = db.prepare('SELECT * FROM files WHERE user_id = ? ORDER BY created_at DESC, id DESC').all(user.id);
    for (const file of files) {
      if (used <= Number(current.quota_bytes)) break;
      try {
        await removeStoredFile(file);
        used = Math.max(0, used - plainStoredFileSize(file));
      } catch (error) {
        console.error(`Paid storage cleanup failed for user ${user.id}, file ${file.id}:`, error);
        // The privacy policy requires newest-complete-file-first deletion.
        // Never skip a failed newest object and continue deleting older files.
        break;
      }
    }
    if (used <= Number(current.quota_bytes)) {
      db.prepare('UPDATE users SET storage_overage_since = NULL WHERE id = ?').run(user.id);
    }
  }
}

async function stopUserUploads(userId) {
  const uploads = q.listUserUploads.all(userId);
  for (const upload of uploads) {
    markUploadCancelled(userId, upload.id);
    const completion = completingUploads.get(uploadKey(userId, upload.id));
    if (completion) {
      completion.cancelled = true;
      completion.output?.destroy();
    }
  }
  await Promise.all(uploads.map(removeUpload));
}

async function finalizeAccountDeletion(deletion) {
  if (finalizingAccountDeletions.has(deletion.id)) return;
  finalizingAccountDeletions.add(deletion.id);
  try {
    const current = db.prepare(`SELECT * FROM account_deletions
      WHERE id = ? AND status = 'scheduled' AND scheduled_for <= ?`).get(deletion.id, Date.now());
    if (!current) return;
    await stopUserUploads(current.user_id);
    await fsp.rm(path.join(FILE_ROOT, String(current.user_id)), { recursive: true, force: true });
    const completedAt = Date.now();
    db.transaction(() => {
      db.prepare('DELETE FROM sessions WHERE user_id = ?').run(current.user_id);
      db.prepare('DELETE FROM files WHERE user_id = ?').run(current.user_id);
      db.prepare('DELETE FROM uploads WHERE user_id = ?').run(current.user_id);
      db.prepare('DELETE FROM users WHERE id = ?').run(current.user_id);
      db.prepare(`UPDATE account_deletions SET status = 'erased_pending_notification', completed_at = ?
        WHERE id = ? AND status = 'scheduled'`).run(completedAt, current.id);
    })();
  } catch (error) {
    console.error('Account deletion finalization failed:', error);
  } finally {
    finalizingAccountDeletions.delete(deletion.id);
  }
}

async function deliverDeletionCompletedNotice(deletion) {
  const result = await transactionalMailRequest({
    to: deletion.email,
    ...deletionCompletedMessage(deletion)
  });
  if (!result.ok) return;
  db.prepare(`DELETE FROM account_deletions
    WHERE id = ? AND status = 'erased_pending_notification'`).run(deletion.id);
}

async function removeLegacyFile(file) {
  db.prepare('DELETE FROM files WHERE id = ?').run(file.id);
  await fsp.rm(path.join(FILE_ROOT, String(file.user_id), file.stored_name), { force: true });
}

async function cleanup() {
  const now = Date.now();
  try {
    const reminderSummary = await membershipExpiryReminderService.deliverDue(now);
    if (reminderSummary.sent || reminderSummary.failed) {
      console.info('Membership expiry reminder run:', reminderSummary);
    }
  } catch (error) {
    console.error('Membership expiry reminder scan failed:', error);
  }
  for (const user of db.prepare('SELECT id FROM users').all()) refreshUserEntitlements(user.id, now);
  await cleanupExpiredPaidStorage(now);
  const stale = db.prepare('SELECT * FROM uploads WHERE created_at < ?').all(now - UPLOAD_TTL);
  const unencryptedUploads = db.prepare('SELECT * FROM uploads WHERE encryption_version != ?').all(ENCRYPTION_VERSION);
  const incompatible = db.prepare('SELECT * FROM uploads').all()
    .filter(upload => !Number.isSafeInteger(upload.chunk_size) || upload.chunk_size <= 0
      || upload.chunk_count !== Math.max(1, Math.ceil(upload.size / upload.chunk_size)));
  const removable = [...new Map([...stale, ...unencryptedUploads, ...incompatible].map(upload => [upload.id, upload])).values()];
  await Promise.all(removable.map(removeUpload));
  const legacyFiles = db.prepare('SELECT * FROM files WHERE encryption_version != ?').all(ENCRYPTION_VERSION);
  await Promise.all(legacyFiles.map(removeLegacyFile));
  db.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(now);
  q.deleteExpiredPasswordResets.run(now);
  q.deleteExpiredVaultPasskeyChallenges.run(now);
  q.deleteExpiredVaultRecoveryResetProofs.run(now);
  q.deleteExpiredPasskeyActionChallenges.run(now);
  q.deleteExpiredPasskeyActionProofs.run(now);
  q.deleteExpiredPasskeyLoginChallenges.run(now);
  q.deleteStalePendingVaultPasskeys.run(now - PASSKEY_CHALLENGE_TTL);
  for (const [key, expiresAt] of cancelledUploads) {
    if (expiresAt <= now) cancelledUploads.delete(key);
  }
  for (const deletion of q.dueDeletions.all(now)) await finalizeAccountDeletion(deletion);
  for (const deletion of q.pendingDeletionNotices.all()) {
    try {
      await deliverDeletionCompletedNotice(deletion);
    } catch (error) {
      console.error('Account deletion completion email failed:', error);
    }
  }
}

await cleanup();
setInterval(() => cleanup().catch(console.error), ACCOUNT_DELETION_CHECK_INTERVAL).unref();
cleanupAdminAuditLogs();
setInterval(() => {
  try { cleanupAdminAuditLogs(); }
  catch (error) { console.error('Admin audit cleanup failed:', error); }
}, ADMIN_AUDIT_CLEANUP_INTERVAL).unref();

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({
  crossOriginEmbedderPolicy: { policy: 'require-corp' },
  frameguard: { action: 'deny' },
  contentSecurityPolicy: {
    directives: {
      'default-src': ["'none'"],
      'base-uri': ["'none'"],
      'connect-src': ["'self'"],
      'font-src': ["'self'"],
      'form-action': ["'self'"],
      'frame-ancestors': ["'none'"],
      'frame-src': ["'none'"],
      'img-src': ["'self'", 'data:', 'blob:'],
      'manifest-src': ["'self'"],
      'media-src': ['blob:'],
      'object-src': ["'none'"],
      'script-src': ["'self'"],
      'script-src-attr': ["'none'"],
      'style-src': ["'self'"],
      'trusted-types': ['yuni-share'],
      'require-trusted-types-for': ["'script'"],
      'worker-src': ["'self'"],
      'upgrade-insecure-requests': []
    }
  }
}));
app.use((req, res, next) => {
  res.set('Permissions-Policy', [
    'accelerometer=()', 'ambient-light-sensor=()', 'autoplay=()', 'bluetooth=()',
    'browsing-topics=()', 'camera=()', 'display-capture=()', 'geolocation=()',
    'gyroscope=()', 'magnetometer=()', 'microphone=()', 'payment=()',
    'publickey-credentials-create=(self)', 'publickey-credentials-get=(self)',
    'serial=()', 'usb=()'
  ].join(', '));
  if (req.path === '/api' || req.path.startsWith('/api/')) {
    res.set({
      'Cache-Control': 'no-store, no-transform, max-age=0',
      'Pragma': 'no-cache',
      'Surrogate-Control': 'no-store'
    });
  }
  next();
});
app.use(originGuard);
const defaultJsonParser = express.json({ limit: '32kb' });
const avatarJsonParser = express.json({ limit: '64mb' });
app.use((req, res, next) => {
  const parser = req.method === 'POST' && req.path === '/api/profile/avatar'
    ? avatarJsonParser
    : defaultJsonParser;
  parser(req, res, next);
});
app.use(express.urlencoded({ extended: false, limit: '32kb' }));
app.use('/avatars', express.static(AVATAR_ROOT, { maxAge: '1d', etag: true }));

app.get('/health', (req, res) => res.json({ ok: true }));

app.post('/api/admin/login', async (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  // A timing-safe comparison prevents an unauthenticated endpoint from
  // revealing either part of the administrator credential.
  const usernameMatches = ADMIN_USERNAME && username.length === ADMIN_USERNAME.length
    && crypto.timingSafeEqual(Buffer.from(username), Buffer.from(ADMIN_USERNAME));
  const passwordMatches = ADMIN_PASSWORD && password.length === ADMIN_PASSWORD.length
    && crypto.timingSafeEqual(Buffer.from(password), Buffer.from(ADMIN_PASSWORD));
  if (!usernameMatches || !passwordMatches) return jsonError(res, 401, '管理员用户名或密码错误');
  setAdminSession(res);
  res.json({ ok: true, username: ADMIN_USERNAME });
});

app.post('/api/admin/logout', (req, res) => { clearAdminSession(req, res); res.json({ ok: true }); });
app.get('/api/admin/session', requireAdmin, (req, res) => res.json({ ok: true, username: ADMIN_USERNAME,
  passkeyCount: db.prepare('SELECT COUNT(*) AS count FROM admin_passkeys').get().count }));

app.get('/api/admin/passkeys', requireAdmin, (req, res) => {
  const passkeys = db.prepare(`SELECT credential_id, transports, created_at, last_used_at
    FROM admin_passkeys ORDER BY created_at ASC`).all().map(row => ({
      credentialId: row.credential_id,
      transports: storedPasskeyTransports(row.transports),
      createdAt: row.created_at,
      lastUsedAt: row.last_used_at
    }));
  res.json({ passkeys });
});

app.delete('/api/admin/passkeys/:credentialId', requireAdmin, (req, res) => {
  const credentialId = base64url(req.params.credentialId, 16, 1024);
  if (!credentialId) return jsonError(res, 400, 'Passkey 标识无效');
  const removed = db.prepare('DELETE FROM admin_passkeys WHERE credential_id = ?').run(credentialId);
  if (!removed.changes) return jsonError(res, 404, 'Passkey 不存在或已被删除');
  res.json({ ok: true });
});

app.post('/api/admin/passkeys/registration/options', requireAdmin, async (req, res) => {
  const existing = db.prepare('SELECT credential_id, transports FROM admin_passkeys').all().map(row => ({
    id: row.credential_id, transports: storedPasskeyTransports(row.transports)
  }));
  const options = await generateRegistrationOptions({
    rpName: 'Yuni Share Administration', rpID: WEBAUTHN_RP_ID,
    userID: Buffer.from(`yuni-share-admin:${ADMIN_USERNAME}`), userName: ADMIN_USERNAME,
    userDisplayName: 'Yuni Share Administrator', attestationType: 'none', excludeCredentials: existing,
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' }
  });
  res.json({ challengeId: createAdminPasskeyChallenge('register', options.challenge), options });
});

app.post('/api/admin/passkeys/registration/verify', requireAdmin, async (req, res) => {
  const challenge = consumeAdminPasskeyChallenge(req.body.challengeId, 'register');
  if (!challenge) return jsonError(res, 400, 'Passkey 注册请求无效、已过期或已使用');
  let verification;
  try { verification = await verifyRegistrationResponse({ response: req.body.response, expectedChallenge: challenge.challenge, expectedOrigin: PUBLIC_ORIGIN, expectedRPID: WEBAUTHN_RP_ID, requireUserVerification: true }); }
  catch { return jsonError(res, 400, '无法验证管理员 Passkey 注册'); }
  if (!verification.verified || !verification.registrationInfo?.userVerified) return jsonError(res, 401, 'Passkey 未完成设备验证');
  const info = verification.registrationInfo; const credentialId = base64url(info.credential.id, 16, 1024);
  if (!credentialId) return jsonError(res, 400, 'Passkey 标识无效');
  try {
    db.prepare('INSERT INTO admin_passkeys(credential_id, public_key, counter, transports, created_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?)')
      .run(credentialId, Buffer.from(info.credential.publicKey).toString('base64url'), info.credential.counter, JSON.stringify(passkeyTransports(req.body.response?.response?.transports)), Date.now(), Date.now());
  } catch (error) { if (error.code === 'SQLITE_CONSTRAINT_PRIMARYKEY') return jsonError(res, 409, '此 Passkey 已添加'); throw error; }
  res.status(201).json({ ok: true, credentialId });
});

app.post('/api/admin/passkey-login/options', async (req, res) => {
  const passkeys = db.prepare('SELECT credential_id, transports FROM admin_passkeys').all();
  if (!passkeys.length) return jsonError(res, 409, '管理员尚未注册 Passkey，请先使用管理员密码登录后添加');
  const options = await generateAuthenticationOptions({ rpID: WEBAUTHN_RP_ID, userVerification: 'required',
    allowCredentials: passkeys.map(row => ({ id: row.credential_id, transports: storedPasskeyTransports(row.transports) })) });
  res.json({ challengeId: createAdminPasskeyChallenge('login', options.challenge), options });
});

app.post('/api/admin/passkey-login/verify', async (req, res) => {
  const credentialId = base64url(req.body.response?.id, 16, 1024); const challenge = consumeAdminPasskeyChallenge(req.body.challengeId, 'login');
  if (!credentialId || !challenge) return jsonError(res, 400, 'Passkey 登录请求无效、已过期或已使用');
  const passkey = db.prepare('SELECT * FROM admin_passkeys WHERE credential_id = ?').get(credentialId);
  if (!passkey) return jsonError(res, 401, '此 Passkey 未获管理员授权');
  let verification;
  try { verification = await verifyAuthenticationResponse({ response: req.body.response, expectedChallenge: challenge.challenge, expectedOrigin: PUBLIC_ORIGIN, expectedRPID: WEBAUTHN_RP_ID, credential: webauthnCredential(passkey), requireUserVerification: true }); }
  catch { return jsonError(res, 400, '无法验证管理员 Passkey 登录'); }
  if (!verification.verified || verification.authenticationInfo.credentialID !== credentialId) return jsonError(res, 401, '管理员 Passkey 登录验证失败');
  db.prepare('UPDATE admin_passkeys SET counter = ?, last_used_at = ? WHERE credential_id = ?').run(verification.authenticationInfo.newCounter, Date.now(), credentialId);
  setAdminSession(res); res.json({ ok: true, username: ADMIN_USERNAME });
});

function adminContentPayload(row) {
  return {
    key: row.content_key,
    label: SITE_CONTENT_DEFINITIONS.get(row.content_key)?.label || row.content_key,
    title: row.title,
    intro: row.intro,
    meta: row.meta,
    bodyHtml: row.body_html,
    enabled: Number(row.enabled) === 1,
    updatedAt: row.updated_at
  };
}

app.get('/api/admin/dashboard', requireAdmin, async (req, res) => {
  const usedBytes = db.prepare(`SELECT COALESCE(SUM(
    CASE WHEN encryption_version = ${ENCRYPTION_VERSION} AND logical_size IS NOT NULL THEN logical_size
      WHEN encryption_version = ${ENCRYPTION_VERSION} AND chunk_count > 0 THEN MAX(0, size - chunk_count * ${GCM_TAG_BYTES})
      ELSE size END), 0) AS bytes FROM files`).get().bytes;
  const stats = {
    users: db.prepare('SELECT COUNT(*) AS count FROM users').get().count,
    files: db.prepare('SELECT COUNT(*) AS count FROM files').get().count,
    usedBytes,
    uploads: db.prepare('SELECT COUNT(*) AS count FROM uploads').get().count,
    activeMemberships: db.prepare('SELECT COUNT(*) AS count FROM subscriptions WHERE expires_at > ?').get(Date.now()).count,
    scheduledDeletions: db.prepare("SELECT COUNT(*) AS count FROM account_deletions WHERE status = 'scheduled'").get().count
  };
  const recentAudit = db.prepare(`SELECT a.id, a.action, a.target_user_id, a.details, a.created_at, u.username, u.email
    FROM admin_audit_logs a LEFT JOIN users u ON u.id = a.target_user_id
    ORDER BY a.created_at DESC, a.id DESC LIMIT 8`).all().map(row => {
    let details = {};
    try { details = JSON.parse(row.details); } catch {}
    return { ...row, details };
  });
  let storage = { configured: STORAGE_ENABLED, ok: false, service: '未连接' };
  if (STORAGE_ENABLED) {
    try {
      const response = await storageRequest('/health');
      const health = await response.json().catch(() => ({}));
      storage = { configured: true, ok: response.ok && health.ok !== false, service: health.service || 'Storage' };
    } catch {}
  }
  res.json({ stats, storage, recentAudit });
});

app.get('/api/admin/site-content', requireAdmin, (req, res) => {
  const content = [...SITE_CONTENT_DEFINITIONS.keys()].map(key => {
    const row = db.prepare('SELECT * FROM site_content WHERE content_key = ?').get(key);
    return row ? adminContentPayload(row) : null;
  }).filter(Boolean);
  res.json({ content });
});

app.get('/api/admin/site-content/:key/revisions', requireAdmin, (req, res) => {
  const key = String(req.params.key || '');
  if (!SITE_CONTENT_KEYS.has(key)) return jsonError(res, 400, '内容类型无效');
  const revisions = db.prepare(`SELECT id, content_key AS key, title, intro, meta, body_html AS bodyHtml, enabled, created_at AS createdAt
    FROM site_content_revisions WHERE content_key = ? ORDER BY created_at DESC, id DESC LIMIT 30`).all(key);
  res.json({ revisions });
});

app.put('/api/admin/site-content/:key', requireAdmin, (req, res) => {
  const key = String(req.params.key || '');
  if (!SITE_CONTENT_KEYS.has(key)) return jsonError(res, 400, '内容类型无效');
  const current = db.prepare('SELECT * FROM site_content WHERE content_key = ?').get(key);
  if (!current) return jsonError(res, 404, '内容不存在');
  const title = String(req.body.title || '').trim().slice(0, 160);
  const intro = String(req.body.intro || '').trim().slice(0, 600);
  const meta = String(req.body.meta || '').trim().slice(0, 600);
  const bodyHtml = sanitizeSiteHtml(req.body.bodyHtml || '');
  const enabled = key === 'announcement' && req.body.enabled === true ? 1 : key === 'announcement' ? 0 : 1;
  if (!title || bodyHtml.length > 500_000) return jsonError(res, 400, '标题不能为空，正文不能超过 500 KB');
  const changed = current.title !== title || current.intro !== intro || current.meta !== meta
    || current.body_html !== bodyHtml || Number(current.enabled) !== enabled;
  if (!changed) return res.json({ ok: true, content: adminContentPayload(current), unchanged: true });
  const now = Date.now();
  db.transaction(() => {
    db.prepare(`INSERT INTO site_content_revisions(content_key, title, intro, meta, body_html, enabled, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)`).run(key, current.title, current.intro, current.meta, current.body_html, current.enabled, now);
    db.prepare(`UPDATE site_content SET title = ?, intro = ?, meta = ?, body_html = ?, enabled = ?, updated_at = ?
      WHERE content_key = ?`).run(title, intro, meta, bodyHtml, enabled, now, key);
    auditAdmin('site_content_updated', 0, { key, title, enabled, revisionCreatedAt: now });
  })();
  res.json({ ok: true, content: adminContentPayload(db.prepare('SELECT * FROM site_content WHERE content_key = ?').get(key)) });
});

app.post('/api/admin/site-content/:key/unpublish', requireAdmin, (req, res) => {
  const key = String(req.params.key || '');
  if (key !== 'announcement') return jsonError(res, 400, '只有站内公告可以撤销发布');
  const current = db.prepare('SELECT * FROM site_content WHERE content_key = ?').get(key);
  if (!current) return jsonError(res, 404, '公告不存在');
  if (Number(current.enabled) !== 1) return res.json({ ok: true, content: adminContentPayload(current), unchanged: true });
  const now = Date.now();
  db.transaction(() => {
    db.prepare(`INSERT INTO site_content_revisions(content_key, title, intro, meta, body_html, enabled, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)`).run(key, current.title, current.intro, current.meta, current.body_html, current.enabled, now);
    db.prepare('UPDATE site_content SET enabled = 0, updated_at = ? WHERE content_key = ?').run(now, key);
    auditAdmin('site_content_unpublished', 0, { key, revisionCreatedAt: now });
  })();
  res.json({ ok: true, content: adminContentPayload(db.prepare('SELECT * FROM site_content WHERE content_key = ?').get(key)) });
});

app.post('/api/admin/site-content/:key/revisions/:id/restore', requireAdmin, (req, res) => {
  const key = String(req.params.key || '');
  const revisionId = Number(req.params.id);
  if (!SITE_CONTENT_KEYS.has(key) || !Number.isSafeInteger(revisionId) || revisionId < 1) return jsonError(res, 400, '恢复记录无效');
  const current = db.prepare('SELECT * FROM site_content WHERE content_key = ?').get(key);
  const revision = db.prepare('SELECT * FROM site_content_revisions WHERE id = ? AND content_key = ?').get(revisionId, key);
  if (!current || !revision) return jsonError(res, 404, '恢复记录不存在');
  const now = Date.now();
  db.transaction(() => {
    db.prepare(`INSERT INTO site_content_revisions(content_key, title, intro, meta, body_html, enabled, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)`).run(key, current.title, current.intro, current.meta, current.body_html, current.enabled, now);
    db.prepare(`UPDATE site_content SET title = ?, intro = ?, meta = ?, body_html = ?, enabled = ?, updated_at = ?
      WHERE content_key = ?`).run(revision.title, revision.intro, revision.meta, revision.body_html, key === 'announcement' ? revision.enabled : 1, now, key);
    auditAdmin('site_content_restored', 0, { key, revisionId });
  })();
  res.json({ ok: true, content: adminContentPayload(db.prepare('SELECT * FROM site_content WHERE content_key = ?').get(key)) });
});

app.get('/api/admin/users', requireAdmin, (req, res) => {
  const search = String(req.query.search || '').trim();
  const term = `%${search.replace(/[\\%_]/g, '\\$&')}%`;
  const status = ['all', 'scheduled', 'active'].includes(String(req.query.status || 'all')) ? String(req.query.status || 'all') : 'all';
  const requestedPage = Number(req.query.page || 1);
  const page = Number.isSafeInteger(requestedPage) && requestedPage > 0 ? requestedPage : 1;
  const statusFilter = status === 'scheduled'
    ? `AND EXISTS (SELECT 1 FROM account_deletions ad_filter WHERE ad_filter.user_id = u.id AND ad_filter.status = 'scheduled')`
    : status === 'active'
      ? `AND NOT EXISTS (SELECT 1 FROM account_deletions ad_filter WHERE ad_filter.user_id = u.id AND ad_filter.status = 'scheduled')`
      : '';
  const where = `(? = '' OR u.email LIKE ? ESCAPE '\\' OR u.username LIKE ? ESCAPE '\\') ${statusFilter}`;
  const total = db.prepare(`SELECT COUNT(*) AS total FROM users u WHERE ${where}`).get(search, term, term).total;
  const totalPages = Math.max(1, Math.ceil(total / ADMIN_USER_PAGE_SIZE));
  const currentPage = Math.min(page, totalPages);
  const selectUsers = () => db.prepare(`SELECT u.id, u.email, u.username, u.quota_bytes, u.created_at,
    COALESCE((SELECT SUM(CASE WHEN f.encryption_version = ${ENCRYPTION_VERSION} AND f.logical_size IS NOT NULL
      THEN f.logical_size
      WHEN f.encryption_version = ${ENCRYPTION_VERSION} AND f.chunk_count > 0
      THEN MAX(0, f.size - f.chunk_count * ${GCM_TAG_BYTES}) ELSE f.size END) FROM files f WHERE f.user_id = u.id), 0) AS used_bytes,
    s.plan_id, s.expires_at,
    CASE WHEN s.user_id IS NOT NULL AND s.expires_at > ? THEN 1 ELSE 0 END AS membership_active,
    ad.status AS deletion_status, ad.requested_at AS deletion_requested_at,
    ad.scheduled_for AS deletion_scheduled_for, ad.retention_days AS deletion_retention_days
    FROM users u LEFT JOIN subscriptions s ON s.user_id = u.id
    LEFT JOIN account_deletions ad ON ad.user_id = u.id AND ad.status = 'scheduled'
    WHERE ${where}
    ORDER BY CASE WHEN ad.status = 'scheduled' THEN 0 ELSE 1 END, u.created_at DESC
    LIMIT ? OFFSET ?`).all(Date.now(), search, term, term, ADMIN_USER_PAGE_SIZE, (currentPage - 1) * ADMIN_USER_PAGE_SIZE);
  let users = selectUsers();
  for (const user of users) refreshUserEntitlements(user.id);
  users = selectUsers();
  const addonsForUser = db.prepare(`SELECT id, addon_id, quota_bytes, expires_at, created_at
    FROM storage_addons WHERE user_id = ? AND expires_at > ? ORDER BY created_at DESC, id DESC`);
  users = users.map(user => {
    const storageAddons = addonsForUser.all(user.id, Date.now());
    return {
      ...user,
      storage_addons: storageAddons,
      addon_count: storageAddons.length,
      addon_quota_bytes: storageAddons.reduce((sum, addon) => sum + Number(addon.quota_bytes), 0)
    };
  });
  res.json({ users, page: currentPage, pageSize: ADMIN_USER_PAGE_SIZE, total, totalPages, status });
});

app.get('/api/admin/users/:id/audit', requireAdmin, (req, res) => {
  const userId = Number(req.params.id);
  if (!Number.isSafeInteger(userId) || userId < 1) return jsonError(res, 400, '用户 ID 无效');
  const audit = db.prepare('SELECT id, action, details, created_at FROM admin_audit_logs WHERE target_user_id = ? ORDER BY created_at DESC LIMIT 100').all(userId)
    .map(row => ({ ...row, details: JSON.parse(row.details) }));
  res.json({ audit });
});

app.get('/api/admin/audit', requireAdmin, (req, res) => {
  const search = String(req.query.search || '').trim();
  const term = `%${search.replace(/[\\%_]/g, '\\$&')}%`;
  const requestedPage = Number(req.query.page || 1);
  const page = Number.isSafeInteger(requestedPage) && requestedPage > 0 ? requestedPage : 1;
  const where = `(? = '' OR COALESCE(u.email, '') LIKE ? ESCAPE '\\' OR u.username LIKE ? ESCAPE '\\')`;
  const total = db.prepare(`SELECT COUNT(*) AS total
    FROM admin_audit_logs a LEFT JOIN users u ON u.id = a.target_user_id
    WHERE ${where}`).get(search, term, term).total;
  const totalPages = Math.max(1, Math.ceil(total / ADMIN_AUDIT_PAGE_SIZE));
  const currentPage = Math.min(page, totalPages);
  const audit = db.prepare(`SELECT a.id, a.action, a.target_user_id, a.details, a.created_at, u.username, u.email
    FROM admin_audit_logs a LEFT JOIN users u ON u.id = a.target_user_id
    WHERE ${where}
    ORDER BY a.created_at DESC, a.id DESC
    LIMIT ? OFFSET ?`).all(search, term, term, ADMIN_AUDIT_PAGE_SIZE, (currentPage - 1) * ADMIN_AUDIT_PAGE_SIZE)
    .map(row => {
      let details = {};
      try { details = JSON.parse(row.details); } catch {}
      return { ...row, details };
    });
  res.json({ audit, page: currentPage, pageSize: ADMIN_AUDIT_PAGE_SIZE, total, totalPages });
});

app.post('/api/admin/users/:id/quota', requireAdmin, (req, res) => {
  const userId = Number(req.params.id);
  const quotaBytes = Number(req.body.quotaBytes);
  const reason = String(req.body.reason || '').trim().slice(0, 500);
  if (!Number.isSafeInteger(userId) || userId < 1 || !Number.isSafeInteger(quotaBytes)
    || quotaBytes < 1024 ** 3 || quotaBytes > 2 * 1024 ** 4 || !reason) {
    return jsonError(res, 400, '请输入 1 GB 至 2 TB 的整数配额，以及调整原因');
  }
  const user = q.userById.get(userId);
  if (!user) return jsonError(res, 404, '用户不存在');
  const used = Number(q.usage.get(userId).bytes);
  const overageSince = used > quotaBytes
    ? Number(user.storage_overage_since) || Date.now()
    : null;
  db.transaction(() => {
    db.prepare('UPDATE users SET quota_bytes = ?, storage_overage_since = ? WHERE id = ?')
      .run(quotaBytes, overageSince, userId);
    auditAdmin('quota_adjusted', userId, { previousQuotaBytes: user.quota_bytes, quotaBytes, reason });
  })();
  if (user.email) void transactionalMailRequest({
    to: user.email, subject: 'Yuni Share · Storage Quota Updated',
    text: `Hello,\n\nAn administrator has adjusted your encrypted storage quota to ${Math.round(quotaBytes / 1024 ** 3)} GB.\n\nAdministrator's note: ${reason}\n\nIf you believe this was made in error, please contact support.`
  }).catch(() => {});
  res.json({ ok: true, quotaBytes });
});

app.post('/api/admin/users/:id/refund-revoke-membership', requireAdmin, (req, res) => {
  const userId = Number(req.params.id);
  const reason = String(req.body.reason || '').trim().slice(0, 500);
  if (!Number.isSafeInteger(userId) || userId < 1 || !reason) return jsonError(res, 400, '请提供退款处理说明');
  const user = q.userById.get(userId);
  if (!user) return jsonError(res, 404, '用户不存在');
  const previous = db.transaction(() => {
    const membership = db.prepare('SELECT plan_id, quota_bytes, expires_at FROM subscriptions WHERE user_id = ?').get(userId);
    if (!membership || Number(membership.expires_at) <= Date.now()) return null;
    const storageAddons = db.prepare(`SELECT id, addon_id, quota_bytes, expires_at, created_at
      FROM storage_addons WHERE user_id = ? ORDER BY created_at ASC, id ASC`).all(userId);
    db.prepare('DELETE FROM subscriptions WHERE user_id = ?').run(userId);
    db.prepare('DELETE FROM storage_addons WHERE user_id = ?').run(userId);
    const used = Number(q.usage.get(userId).bytes);
    db.prepare('UPDATE users SET quota_bytes = ?, storage_overage_since = ? WHERE id = ?')
      .run(USER_QUOTA, used > USER_QUOTA ? Date.now() : null, userId);
    auditAdmin('refund_revoked_membership', userId, { previousSubscription: membership, previousStorageAddons: storageAddons, restoredQuotaBytes: USER_QUOTA, reason });
    return { membership, storageAddons };
  })();
  if (!previous) return jsonError(res, 409, '该用户当前没有有效会员，无法执行会员退款');
  if (user.email) void transactionalMailRequest({
    to: user.email, subject: 'Yuni Share · Membership Cancelled Following Refund',
    text: `Hello,\n\nYour membership has been cancelled as part of the refund process. Your encrypted storage quota has been restored to ${Math.round(USER_QUOTA / 1024 ** 3)} GB.\n\nAdministrator's note: ${reason}\n\nIf your stored files exceed the free quota, uploads are blocked while preview, download, and deletion remain available. You have 15 days from this cancellation to renew or reduce usage. After that period, the newest complete encrypted files are deleted until usage is within the free quota.`
  }).catch(() => {});
  res.json({ ok: true, quotaBytes: USER_QUOTA });
});

app.post('/api/register/code', async (req, res) => {
  const email = normalizeEmail(req.body.email);
  if (!email) return jsonError(res, 400, '请输入有效的邮箱地址');
  if (INVITE_REGISTRATION_ENABLED && INVITE_CODE && req.body.inviteCode !== INVITE_CODE) return jsonError(res, 403, '注册码不正确');
  if (q.userByEmail.get(email)) return jsonError(res, 409, '该邮箱已注册');
  const result = await mailRequest('issue', email, '', requestIp(req));
  if (!result.ok) return jsonError(res, result.status || 503, result.error || '验证码发送失败');
  res.status(202).json({ ok: true, retryAfterSeconds: result.retryAfterSeconds || 60 });
});

app.post('/api/register', async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  const code = String(req.body.code || '').trim().toUpperCase();
  const encryption = vaultConfig(req.body.encryption);
  const recovery = vaultRecoveryConfig(req.body.recovery);
  if (!email) return jsonError(res, 400, '请输入有效的邮箱地址');
  if (!validUsername(username)) return jsonError(res, 400, '用户名需为 3-32 位字母、数字或下划线');
  if (password.length < 10 || password.length > 128) return jsonError(res, 400, '密码需为 10-128 个字符');
  if (!validCode(code)) return jsonError(res, 400, '请输入 6 位邮箱验证码');
  if (!encryption || (req.body.recovery && !recovery)) {
    return jsonError(res, 400, '浏览器未能创建端到端加密材料，请刷新页面后重试');
  }
  if (INVITE_REGISTRATION_ENABLED && INVITE_CODE && req.body.inviteCode !== INVITE_CODE) return jsonError(res, 403, '注册码不正确');
  if (q.userByEmail.get(email)) return jsonError(res, 409, '该邮箱已注册');
  const passwordHash = await bcrypt.hash(password, 12);
  const verified = await mailRequest('verify', email, code, requestIp(req));
  if (!verified.ok || !verified.verified) return jsonError(res, verified.status || 401, verified.error || '验证码不正确或已过期');
  try {
    const result = db.prepare(`INSERT INTO users(
      public_id, email, username, password_hash, quota_bytes, created_at,
      encryption_version, vault_salt, vault_key_iv, vault_wrapped_key, vault_kdf_iterations,
      vault_recovery_salt, vault_recovery_iv, vault_recovery_wrapped_key, vault_recovery_kdf_iterations
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      crypto.randomUUID(), email, username, passwordHash, USER_QUOTA, Date.now(),
      encryption.version, encryption.salt, encryption.iv, encryption.wrappedKey, encryption.iterations,
      recovery?.salt || null, recovery?.iv || null, recovery?.wrappedKey || null, recovery?.iterations || null
    );
    await fsp.mkdir(path.join(FILE_ROOT, String(result.lastInsertRowid)), { recursive: true });
    setSession(res, result.lastInsertRowid);
    res.status(201).json({ ok: true });
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') return jsonError(res, 409, '邮箱已存在');
    throw error;
  }
});

app.post('/api/login', async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const password = String(req.body.password || '');
  const user = email && q.userByEmail.get(email);
  const valid = user && await bcrypt.compare(password, user.password_hash);
  if (!valid) return jsonError(res, 401, '邮箱或密码错误');
  if (q.scheduledDeletion.get(user.id)) {
    return jsonError(res, 403, '该账户已安排删除，因此当前不能登录。请使用删除确认邮件中的恢复链接，在所选恢复期结束前撤销删除。');
  }
  setSession(res, user.id);
  res.json({ ok: true });
});

app.post('/api/passkey-login/options', async (req, res) => {
  const options = await generateAuthenticationOptions({
    rpID: WEBAUTHN_RP_ID,
    userVerification: 'required',
    extensions: passkeyAuthenticationExtensions()
  });
  const challengeId = createPasskeyLoginChallenge(options.challenge);
  res.json({ challengeId, options });
});

app.post('/api/passkey-login/verify', async (req, res) => {
  const credentialId = base64url(req.body.response?.id, 16, 1024);
  if (!credentialId) return jsonError(res, 400, 'Passkey 响应无效');
  const challenge = consumePasskeyLoginChallenge(req.body.challengeId);
  if (!challenge) return jsonError(res, 400, 'Passkey 登录请求无效、已过期或已使用');
  const passkey = q.activeVaultPasskeyByCredential.get(credentialId);
  if (!passkey) return jsonError(res, 401, 'Passkey 未关联可登录账户');
  const user = q.userById.get(passkey.user_id);
  if (!user) return jsonError(res, 401, 'Passkey 未关联可登录账户');

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: req.body.response,
      expectedChallenge: challenge.challenge,
      expectedOrigin: USER_PASSKEY_ORIGINS,
      expectedRPID: WEBAUTHN_RP_ID,
      credential: webauthnCredential(passkey),
      requireUserVerification: true
    });
  } catch {
    return jsonError(res, 400, '无法验证 Passkey 登录');
  }
  if (!verification.verified || verification.authenticationInfo.credentialID !== credentialId) {
    return jsonError(res, 401, 'Passkey 登录验证失败');
  }
  if (q.scheduledDeletion.get(user.id)) {
    return jsonError(res, 403, '该账户已安排删除，因此当前不能登录。请使用删除确认邮件中的恢复链接，在所选恢复期结束前撤销删除。');
  }
  q.updateVaultPasskeyUse.run(
    verification.authenticationInfo.newCounter,
    verification.authenticationInfo.credentialDeviceType,
    verification.authenticationInfo.credentialBackedUp ? 1 : 0,
    Date.now(),
    credentialId,
    user.id
  );
  setSession(res, user.id);
  res.json({ ok: true, credentialId });
});

app.post('/api/password-reset/request', async (req, res) => {
  const email = normalizeEmail(req.body.email);
  if (!email) return jsonError(res, 400, '请输入有效的邮箱地址');
  const user = q.userByEmail.get(email);
  // Explicit account feedback requested for the reset flow. Never send mail for unknown addresses.
  if (!user) return res.status(404).json({ error: '该用户还不存在，你可以注册一个账户', code: 'ACCOUNT_NOT_FOUND' });

  const resetToken = token();
  const createdAt = Date.now();
  try {
    db.transaction(() => {
      q.deleteUserPasswordResets.run(user.id);
      db.prepare(`INSERT INTO password_resets(token_hash, user_id, email, expires_at, created_at)
        VALUES (?, ?, ?, ?, ?)`).run(
        hashToken(resetToken), user.id, email, createdAt + PASSWORD_RESET_TTL, createdAt
      );
    })();
    const delivery = await transactionalMailRequest({
      to: email,
      ...passwordResetMessage(resetToken)
    });
    if (!delivery.ok) {
      q.deleteUserPasswordResets.run(user.id);
      return jsonError(res, delivery.status || 503, delivery.error || '密码重置邮件发送失败');
    }
    res.status(202).json({ ok: true, retryAfterSeconds: 60 });
  } catch (error) {
    q.deleteUserPasswordResets.run(user.id);
    throw error;
  }
});

app.post('/api/password-reset/complete', async (req, res) => {
  const resetToken = String(req.body.token || '');
  const password = String(req.body.password || '');
  if (!/^[A-Za-z0-9_-]{32,128}$/.test(resetToken)) return jsonError(res, 400, '重置链接无效或已过期');
  if (password.length < 10 || password.length > 128) return jsonError(res, 400, '密码需为 10-128 个字符');
  const reset = q.passwordReset.get(hashToken(resetToken), Date.now());
  if (!reset) return jsonError(res, 400, '重置链接无效、已过期或已使用');
  const passwordHash = await bcrypt.hash(password, 12);
  db.transaction(() => {
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(passwordHash, reset.account_id);
    q.deleteUserSessions.run(reset.account_id);
    q.deleteUserPasswordResets.run(reset.account_id);
  })();
  const deletion = q.scheduledDeletion.get(reset.account_id);
  if (!deletion) setSession(res, reset.account_id);
  res.json({ ok: true, signedIn: !deletion });
});

// Display names are not identities; retired name-based migration must not authenticate them.
app.use('/api/legacy', (req, res) => jsonError(res, 410, '旧账户迁移已结束，请使用邮箱登录'));
app.post('/api/legacy/code', async (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  const email = normalizeEmail(req.body.email);
  const user = q.userByName.get(username);
  const valid = user && !user.email && await bcrypt.compare(password, user.password_hash);
  if (!valid) return jsonError(res, 401, '旧用户名或密码错误，或该账号已绑定邮箱');
  if (!email) return jsonError(res, 400, '请输入有效的邮箱地址');
  if (q.userByEmail.get(email)) return jsonError(res, 409, '该邮箱已被其他账号使用');
  const result = await mailRequest('issue', email, '', requestIp(req));
  if (!result.ok) return jsonError(res, result.status || 503, result.error || '验证码发送失败');
  res.status(202).json({ ok: true, retryAfterSeconds: result.retryAfterSeconds || 60 });
});

app.post('/api/legacy/bind', async (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  const email = normalizeEmail(req.body.email);
  const code = String(req.body.code || '').trim().toUpperCase();
  const user = q.userByName.get(username);
  const valid = user && !user.email && await bcrypt.compare(password, user.password_hash);
  if (!valid) return jsonError(res, 401, '旧用户名或密码错误，或该账号已绑定邮箱');
  if (!email || !validCode(code)) return jsonError(res, 400, '邮箱或验证码格式无效');
  if (q.userByEmail.get(email)) return jsonError(res, 409, '该邮箱已被其他账号使用');
  const verified = await mailRequest('verify', email, code, requestIp(req));
  if (!verified.ok || !verified.verified) return jsonError(res, verified.status || 401, verified.error || '验证码不正确或已过期');
  try {
    db.prepare('UPDATE users SET email = ? WHERE id = ? AND email IS NULL').run(email, user.id);
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') return jsonError(res, 409, '该邮箱已被其他账号使用');
    throw error;
  }
  setSession(res, user.id);
  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  const session = cookies(req).share_session;
  if (session) q.deleteSession.run(hashToken(session));
  res.clearCookie('share_session', {
    path: '/',
    httpOnly: true,
    secure: PUBLIC_URL.startsWith('https://'),
    sameSite: 'strict'
  });
  res.set('Clear-Site-Data', '"cache", "storage"');
  res.json({ ok: true });
});

app.post('/api/account-deletion', requireAuth, async (req, res) => {
  const password = String(req.body.password || '');
  const passkeyProof = String(req.body.passkeyProof || '');
  const retentionDays = Number(req.body.retentionDays);
  const email = normalizeEmail(req.user.email);
  if (!email) return jsonError(res, 409, '请先绑定并验证邮箱后再申请删除账户');
  if (![30, 60].includes(retentionDays)) return jsonError(res, 400, '只能选择 30 天或 60 天恢复期');
  if (q.scheduledDeletion.get(req.user.id)) return jsonError(res, 409, '该账户已在删除流程中');
  const passkeyVerified = passkeyProof
    ? consumePasskeyActionProof(req, 'account-deletion', passkeyProof)
    : null;
  if (passkeyProof && !passkeyVerified) {
    return jsonError(res, 401, 'Passkey 验证已失效。请重新验证后再提交。');
  }
  if (!passkeyVerified && !await bcrypt.compare(password, req.user.password_hash)) {
    return jsonError(res, 401, '账户密码不正确');
  }

  const requestedAt = Date.now();
  const deletion = {
    id: crypto.randomUUID(),
    user_id: req.user.id,
    email,
    username: req.user.username,
    retention_days: retentionDays,
    requested_at: requestedAt,
    scheduled_for: requestedAt + retentionDays * 24 * 60 * 60 * 1000
  };
  const cancellationToken = token();
  let notificationAccepted = false;
  try {
    db.prepare(`INSERT INTO account_deletions(
      id, user_id, email, username, retention_days, requested_at, scheduled_for,
      cancellation_token_hash, status
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'scheduled')`).run(
      deletion.id, deletion.user_id, deletion.email, deletion.username, deletion.retention_days,
      deletion.requested_at, deletion.scheduled_for, hashToken(cancellationToken)
    );
    const delivery = await transactionalMailRequest({
      to: deletion.email,
      ...deletionScheduledMessage(deletion, cancellationToken)
    });
    if (!delivery.ok) {
      db.prepare(`DELETE FROM account_deletions WHERE id = ? AND status = 'scheduled'`).run(deletion.id);
      return jsonError(res, delivery.status || 503, delivery.error || '删除确认邮件发送失败');
    }
    notificationAccepted = true;
    q.deleteUserSessions.run(req.user.id);
    await stopUserUploads(req.user.id).catch(error => console.error('Unable to stop uploads for scheduled deletion:', error));
    res.clearCookie('share_session', { path: '/' });
    res.status(202).json({ ok: true, scheduledFor: deletion.scheduled_for, retentionDays });
  } catch (error) {
    if (!notificationAccepted) {
      db.prepare(`DELETE FROM account_deletions WHERE id = ? AND status = 'scheduled'`).run(deletion.id);
    }
    throw error;
  }
});

app.post('/api/account-deletion/validate', (req,res)=>{
  res.set('Cache-Control','no-store');
  const token=String(req.body.token||'');
  const deletion=/^[A-Za-z0-9_-]{32,128}$/.test(token) ? q.deletionByToken.get(hashToken(token)) : null;
  if(!deletion || deletion.scheduled_for<=Date.now() || !q.userById.get(deletion.user_id)) return res.status(404).json({ok:false});
  res.json({ok:true});
});
app.post('/api/account-deletion/cancel', async (req, res) => {
  const cancellationToken = String(req.body.token || '');
  if (!/^[A-Za-z0-9_-]{32,128}$/.test(cancellationToken)) {
    return jsonError(res, 400, '删除恢复链接无效');
  }
  const deletion = q.deletionByToken.get(hashToken(cancellationToken));
  if (!deletion || deletion.scheduled_for <= Date.now()) {
    return jsonError(res, 404, '删除恢复链接无效、已使用、已过期或账户已删除');
  }
  const user = q.userById.get(deletion.user_id);
  if (!user) return jsonError(res, 404, '删除恢复链接无效、已使用、已过期或账户已删除');
  const cancelled = db.prepare(`DELETE FROM account_deletions
    WHERE id = ? AND status = 'scheduled' AND scheduled_for > ?`).run(deletion.id, Date.now());
  if (!cancelled.changes) return jsonError(res, 409, '删除恢复链接已失效，删除流程无法撤销');
  // Recovery revokes deletion only; the user must sign in explicitly afterward.
  if (user.email) void transactionalMailRequest({
    to: user.email,
    subject: 'Yuni Share · Account Deletion Cancelled',
    text: [
      'Your scheduled account deletion has been cancelled and your account is active again. Your files should be as you left them. Sign in and unlock your encrypted space to review your files.',
      'Privacy: Your file contents and names are encrypted on your device before upload. Restoring your account does not change this protection or recover files that have already been permanently deleted.',
      'Account deletion rules: A deletion request has a recovery period of 30 or 60 days, as selected when the request is made. After that period, the account and its encrypted files are scheduled for permanent deletion. This request has now been cancelled, and its recovery link can no longer be used.',
      'Storage retention rules still apply separately: If paid storage expires and your account is over quota, a 15-day retention period applies. If the account remains over quota after that period, complete encrypted files are permanently deleted, starting with the most recently uploaded, until usage is within quota. Cancelling account deletion does not renew a membership or reverse completed storage cleanup.',
      `Privacy Policy: ${PUBLIC_URL}/privacy`,
      `Retention and Deletion Rules: ${PUBLIC_URL}/privacy#retention-and-deletion`,
      'If you did not request this change, contact our account team at support@020126520.xyz.'
    ].join('\n\n')
  }).catch(() => {});
  res.json({ ok: true });
});

app.post('/api/encryption/setup', requireAuth, async (req, res) => {
  if (req.user.encryption_version === ENCRYPTION_VERSION) return jsonError(res, 409, '端到端加密已启用');
  const password = String(req.body.password || '');
  const encryption = vaultConfig(req.body.encryption);
  const recovery = vaultRecoveryConfig(req.body.recovery);
  if (!encryption || (req.body.recovery && !recovery)) {
    const stalePage = req.body.recovery && !req.body.recovery.salt;
    return jsonError(res, stalePage ? 409 : 400, stalePage
      ? '加密页面已更新。请刷新页面后重试。'
      : '加密密钥配置无效');
  }
  if (!await bcrypt.compare(password, req.user.password_hash)) return jsonError(res, 401, '密码不正确');
  db.prepare(`UPDATE users SET encryption_version = ?, vault_salt = ?, vault_key_iv = ?,
    vault_wrapped_key = ?, vault_kdf_iterations = ?, vault_recovery_salt = ?, vault_recovery_iv = ?,
    vault_recovery_wrapped_key = ?, vault_recovery_kdf_iterations = ? WHERE id = ?`).run(
    encryption.version, encryption.salt, encryption.iv, encryption.wrappedKey, encryption.iterations,
    recovery?.salt || null, recovery?.iv || null, recovery?.wrappedKey || null, recovery?.iterations || null, req.user.id
  );
  res.status(201).json({ ok: true });
});

app.post('/api/encryption/password', requireAuth, async (req, res) => {
  if (req.user.encryption_version !== ENCRYPTION_VERSION) return jsonError(res, 409, '端到端加密空间尚未设置');
  const password = String(req.body.password || '');
  const passkeyProof = String(req.body.passkeyProof || '');
  const encryption = vaultConfig(req.body.encryption);
  if (!encryption) return jsonError(res, 400, '新的加密密钥配置无效');
  const proof = passkeyProof ? consumeVaultRecoveryResetProof(req, passkeyProof) : null;
  if (!proof && !await bcrypt.compare(password, req.user.password_hash)) {
    return jsonError(res, 401, '请使用登录密码或已验证的 Passkey 确认修改');
  }
  db.prepare(`UPDATE users SET vault_salt = ?, vault_key_iv = ?, vault_wrapped_key = ?,
    vault_kdf_iterations = ? WHERE id = ?`).run(
    encryption.salt, encryption.iv, encryption.wrappedKey, encryption.iterations, req.user.id
  );
  res.json({ ok: true });
});

app.post('/api/encryption/recovery-password', requireAuth, async (req, res) => {
  if (req.user.encryption_version !== ENCRYPTION_VERSION) return jsonError(res, 409, '端到端加密空间尚未设置');
  const password = String(req.body.password || '');
  const recovery = vaultRecoveryConfig(req.body.recovery);
  if (!recovery) return jsonError(res, 400, '恢复密码配置无效');
  const hasRecoveryPassword = req.user.vault_recovery_salt && req.user.vault_recovery_kdf_iterations;
  if (hasRecoveryPassword) {
    const proof = consumeVaultRecoveryResetProof(req, req.body.passkeyProof);
    if (!proof) return jsonError(res, 403, '请先使用 Passkey 验证，才能重设恢复密码');
  } else if (!await bcrypt.compare(password, req.user.password_hash)) {
    return jsonError(res, 401, '登录密码不正确');
  }
  db.prepare(`UPDATE users SET vault_recovery_salt = ?, vault_recovery_iv = ?,
    vault_recovery_wrapped_key = ?, vault_recovery_kdf_iterations = ? WHERE id = ?`).run(
    recovery.salt, recovery.iv, recovery.wrappedKey, recovery.iterations, req.user.id
  );
  res.json({ ok: true, replaced: Boolean(hasRecoveryPassword) });
});

app.post('/api/vault-passkeys/registration/options', requireAuth, async (req, res) => {
  if (req.user.encryption_version !== ENCRYPTION_VERSION) {
    return jsonError(res, 409, '请先设置端到端加密空间');
  }
  if (q.listActiveVaultPasskeyRecords.all(req.user.id).length) {
    return jsonError(res, 409, '此加密空间已启用 Passkey。请使用现有 Passkey，或先移除它后再创建新的 Passkey');
  }
  const password = String(req.body.password || '');
  const proof = req.body.passkeyProof
    ? consumePasskeyActionProof(req, 'passkey-management', req.body.passkeyProof)
    : null;
  if (!proof && !await bcrypt.compare(password, req.user.password_hash)) {
    return jsonError(res, 401, '请使用登录密码或已验证的 Passkey 确认添加');
  }

  const existing = q.listVaultPasskeysForRegistration.all(req.user.id).map(passkey => ({
    id: passkey.credential_id,
    transports: storedPasskeyTransports(passkey.transports)
  }));
  const preference = passkeyPreference(req.body.preference);
  const options = await generateRegistrationOptions({
    rpName: 'Yuni Share',
    rpID: WEBAUTHN_RP_ID,
    userID: Buffer.from(`yuni-share:${req.user.id}`),
    userName: req.user.email || req.user.username,
    userDisplayName: req.user.username,
    attestationType: 'none',
    excludeCredentials: existing,
    authenticatorSelection: {
      residentKey: 'required',
      userVerification: 'required'
    },
    ...(preference === 'any' ? {} : { preferredAuthenticatorType: preference })
  });
  const challengeId = createVaultPasskeyChallenge(req, 'register', options.challenge);
  res.json({ challengeId, options });
});

app.post('/api/vault-passkeys/registration/verify', requireAuth, async (req, res) => {
  const challenge = consumeVaultPasskeyChallenge(req, req.body.challengeId, 'register');
  if (!challenge) return jsonError(res, 400, 'Passkey 注册请求无效、已过期或已使用');

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: req.body.response,
      expectedChallenge: challenge.challenge,
      expectedOrigin: USER_PASSKEY_ORIGINS,
      expectedRPID: WEBAUTHN_RP_ID,
      requireUserVerification: true
    });
  } catch {
    return jsonError(res, 400, '无法验证 Passkey 注册');
  }
  if (!verification.verified || !verification.registrationInfo?.userVerified) {
    return jsonError(res, 401, 'Passkey 未完成设备验证');
  }

  const info = verification.registrationInfo;
  const credentialId = base64url(info.credential.id, 16, 1024);
  if (!credentialId) return jsonError(res, 400, 'Passkey 标识无效');
  const attachment = ['platform', 'cross-platform'].includes(req.body.response?.authenticatorAttachment)
    ? req.body.response.authenticatorAttachment : 'unknown';
  const transports = passkeyTransports(req.body.response?.response?.transports);
  try {
    q.insertPendingVaultPasskey.run(
      credentialId,
      req.user.id,
      Buffer.from(info.credential.publicKey).toString('base64url'),
      info.credential.counter,
      JSON.stringify(transports),
      attachment,
      info.credentialDeviceType,
      info.credentialBackedUp ? 1 : 0,
      Date.now()
    );
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT_PRIMARYKEY') {
      return jsonError(res, 409, '此 Passkey 已添加到该账户');
    }
    throw error;
  }

  const options = await generateAuthenticationOptions({
    rpID: WEBAUTHN_RP_ID,
    allowCredentials: [{ id: credentialId, transports }],
    userVerification: 'required',
    extensions: passkeyAuthenticationExtensions()
  });
  const activationChallengeId = createVaultPasskeyChallenge(req, 'activate', options.challenge, credentialId);
  res.status(201).json({
    credentialId,
    activation: { challengeId: activationChallengeId, options }
  });
});

app.post('/api/vault-passkeys/:credentialId/activate', requireAuth, async (req, res) => {
  const credentialId = base64url(req.params.credentialId, 16, 1024);
  const wrapper = vaultPasskeyConfig(req.body.wrapping);
  if (!credentialId || !wrapper) return jsonError(res, 400, 'Passkey 加密配置无效');
  const challenge = consumeVaultPasskeyChallenge(req, req.body.challengeId, 'activate');
  if (!challenge || challenge.credential_id !== credentialId) {
    return jsonError(res, 400, 'Passkey 激活请求无效、已过期或已使用');
  }
  const passkey = q.pendingVaultPasskey.get(credentialId, req.user.id);
  if (!passkey) return jsonError(res, 404, '待激活的 Passkey 不存在');

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: req.body.response,
      expectedChallenge: challenge.challenge,
      expectedOrigin: USER_PASSKEY_ORIGINS,
      expectedRPID: WEBAUTHN_RP_ID,
      credential: webauthnCredential(passkey),
      requireUserVerification: true
    });
  } catch {
    return jsonError(res, 400, '无法验证 Passkey 激活');
  }
  if (!verification.verified || verification.authenticationInfo.credentialID !== credentialId) {
    return jsonError(res, 401, 'Passkey 激活验证失败');
  }

  const now = Date.now();
  const activated = q.activateVaultPasskey.run(
    wrapper.salt,
    wrapper.iv,
    wrapper.wrappedKey,
    verification.authenticationInfo.newCounter,
    verification.authenticationInfo.credentialDeviceType,
    verification.authenticationInfo.credentialBackedUp ? 1 : 0,
    now,
    now,
    credentialId,
    req.user.id
  );
  if (!activated.changes) return jsonError(res, 409, 'Passkey 无法激活');
  // Passkey replaces the legacy recovery-password wrapper after activation succeeds.
  q.clearVaultRecovery.run(req.user.id);
  res.status(201).json({ ok: true, passkey: passkeyClientSummary(q.activeVaultPasskey.get(credentialId, req.user.id)) });
});

app.post('/api/vault-passkeys/unlock/options', requireAuth, async (req, res) => {
  if (req.user.encryption_version !== ENCRYPTION_VERSION) {
    return jsonError(res, 409, '端到端加密空间尚未设置');
  }
  const passkeys = q.listActiveVaultPasskeyRecords.all(req.user.id);
  if (!passkeys.length) return jsonError(res, 409, '该账户尚未添加 Passkey');
  const options = await generateAuthenticationOptions({
    rpID: WEBAUTHN_RP_ID,
    allowCredentials: passkeys.map(passkey => ({
      id: passkey.credential_id,
      transports: storedPasskeyTransports(passkey.transports)
    })),
    userVerification: 'required',
    extensions: passkeyAuthenticationExtensions()
  });
  const challengeId = createVaultPasskeyChallenge(req, 'unlock', options.challenge);
  res.json({ challengeId, options });
});

app.post('/api/vault-passkeys/unlock/verify', requireAuth, async (req, res) => {
  const credentialId = base64url(req.body.response?.id, 16, 1024);
  if (!credentialId) return jsonError(res, 400, 'Passkey 响应无效');
  const challenge = consumeVaultPasskeyChallenge(req, req.body.challengeId, 'unlock');
  if (!challenge) return jsonError(res, 400, 'Passkey 解锁请求无效、已过期或已使用');
  const passkey = q.activeVaultPasskey.get(credentialId, req.user.id);
  if (!passkey) return jsonError(res, 404, '该 Passkey 不存在');

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: req.body.response,
      expectedChallenge: challenge.challenge,
      expectedOrigin: USER_PASSKEY_ORIGINS,
      expectedRPID: WEBAUTHN_RP_ID,
      credential: webauthnCredential(passkey),
      requireUserVerification: true
    });
  } catch {
    return jsonError(res, 400, '无法验证 Passkey');
  }
  if (!verification.verified || verification.authenticationInfo.credentialID !== credentialId) {
    return jsonError(res, 401, 'Passkey 验证失败');
  }
  const now = Date.now();
  q.updateVaultPasskeyUse.run(
    verification.authenticationInfo.newCounter,
    verification.authenticationInfo.credentialDeviceType,
    verification.authenticationInfo.credentialBackedUp ? 1 : 0,
    now,
    credentialId,
    req.user.id
  );
  const shouldIssueResetProof = Boolean(req.body?.grantRecoveryReset || req.body?.grantVaultKeyReset);
  const resetProof = shouldIssueResetProof ? createVaultRecoveryResetProof(req, credentialId) : undefined;
  res.json({
    ok: true,
    credentialId,
    ...(req.body?.grantRecoveryReset && resetProof ? { recoveryResetProof: resetProof } : {}),
    ...(req.body?.grantVaultKeyReset && resetProof ? { vaultKeyResetProof: resetProof } : {})
  });
});

app.post('/api/passkey-actions/:purpose/options', requireAuth, async (req, res) => {
  const purpose = passkeyAction(req.params.purpose);
  if (!purpose) return jsonError(res, 404, '不支持的 Passkey 验证操作');
  const passkeys = q.listActiveVaultPasskeyRecords.all(req.user.id);
  if (!passkeys.length) return jsonError(res, 409, '该账户尚未添加 Passkey');
  const options = await generateAuthenticationOptions({
    rpID: WEBAUTHN_RP_ID,
    allowCredentials: passkeys.map(passkey => ({
      id: passkey.credential_id,
      transports: storedPasskeyTransports(passkey.transports)
    })),
    userVerification: 'required',
    ...(purpose === 'passkey-management' ? { extensions: passkeyAuthenticationExtensions() } : {})
  });
  const challengeId = createPasskeyActionChallenge(req, purpose, options.challenge);
  res.json({ challengeId, options });
});

app.post('/api/passkey-actions/:purpose/verify', requireAuth, async (req, res) => {
  const purpose = passkeyAction(req.params.purpose);
  if (!purpose) return jsonError(res, 404, '不支持的 Passkey 验证操作');
  const credentialId = base64url(req.body.response?.id, 16, 1024);
  if (!credentialId) return jsonError(res, 400, 'Passkey 响应无效');
  const challenge = consumePasskeyActionChallenge(req, req.body.challengeId, purpose);
  if (!challenge) return jsonError(res, 400, 'Passkey 验证请求无效、已过期或已使用');
  const passkey = q.activeVaultPasskey.get(credentialId, req.user.id);
  if (!passkey) return jsonError(res, 404, '该 Passkey 不属于当前账户');

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: req.body.response,
      expectedChallenge: challenge.challenge,
      expectedOrigin: USER_PASSKEY_ORIGINS,
      expectedRPID: WEBAUTHN_RP_ID,
      credential: webauthnCredential(passkey),
      requireUserVerification: true
    });
  } catch {
    return jsonError(res, 400, '无法验证 Passkey');
  }
  if (!verification.verified || verification.authenticationInfo.credentialID !== credentialId) {
    return jsonError(res, 401, 'Passkey 验证失败');
  }
  const now = Date.now();
  q.updateVaultPasskeyUse.run(
    verification.authenticationInfo.newCounter,
    verification.authenticationInfo.credentialDeviceType,
    verification.authenticationInfo.credentialBackedUp ? 1 : 0,
    now,
    credentialId,
    req.user.id
  );
  res.json({ ok: true, passkeyProof: createPasskeyActionProof(req, credentialId, purpose) });
});

app.delete('/api/vault-passkeys/:credentialId', requireAuth, async (req, res) => {
  const credentialId = base64url(req.params.credentialId, 16, 1024);
  const password = String(req.body.password || '');
  const proof = req.body.passkeyProof
    ? consumePasskeyActionProof(req, 'passkey-management', req.body.passkeyProof)
    : null;
  if (!credentialId) return jsonError(res, 400, 'Passkey 无效');
  if (!proof && !await bcrypt.compare(password, req.user.password_hash)) {
    return jsonError(res, 401, '请使用登录密码或已验证的 Passkey 确认移除');
  }
  const removed = q.deleteVaultPasskey.run(credentialId, req.user.id);
  if (!removed.changes) return jsonError(res, 404, 'Passkey 不存在');
  res.json({ ok: true });
});

function paymentSignature(value) {
  return crypto.createHash('md5').update(value).digest('hex');
}

function safeSignatureEqual(actual, expected) {
  const a = Buffer.from(String(actual || ''));
  const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

app.all('/api/payments/zhifux/notify', (req, res) => {
  const data = { ...req.query, ...req.body };
  const orderNo = String(data.orderNo || '');
  const order = db.prepare('SELECT * FROM payment_orders WHERE order_no = ?').get(orderNo);
  const expected = paymentSignature(`${data.state || ''}${PAYMENT_MERCHANT_NUM}${orderNo}${data.amount || ''}${PAYMENT_SECRET}`);
  if (!PAYMENT_ENABLED || !order || String(data.merchantNum || '') !== PAYMENT_MERCHANT_NUM
    || String(data.state || '') !== '1' || !safeSignatureEqual(data.sign, expected)
    || Number(data.amount) !== order.amount_cents / 100) return res.status(400).type('text').send('fail');
  if (order.status !== 'paid') {
    const orderType = order.order_type === 'addon' ? 'addon' : 'subscription';
    const plan = orderType === 'addon' ? STORAGE_ADDONS[order.plan_id] : PLANS[order.plan_id];
    if (!plan) return res.status(400).type('text').send('fail');
    const now = Date.now();
    const expiresAt = now + (orderType === 'subscription' && order.billing_cycle === 'yearly' ? 365 : 30) * 24 * 60 * 60 * 1000;
    let activated = false;
    let effectiveQuota = USER_QUOTA;
    db.transaction(() => {
      const markedPaid = db.prepare(`UPDATE payment_orders SET status = 'paid', paid_at = ?, platform_order_no = ? WHERE order_no = ? AND status = 'pending'`)
        .run(now, String(data.platformOrderNo || ''), orderNo);
      if (!markedPaid.changes) return;
      if (orderType === 'addon') {
        db.prepare(`INSERT INTO storage_addons(user_id, addon_id, quota_bytes, expires_at, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?)`)
          .run(order.user_id, order.plan_id, plan.quota, expiresAt, now, now);
        const subscription = db.prepare('SELECT quota_bytes FROM subscriptions WHERE user_id = ? AND expires_at > ?').get(order.user_id, now);
        const addonQuota = db.prepare(`SELECT COALESCE(SUM(quota_bytes), 0) AS total
          FROM storage_addons WHERE user_id = ? AND expires_at > ?`).get(order.user_id, now);
        effectiveQuota = subscription ? Number(subscription.quota_bytes) + Number(addonQuota.total) : USER_QUOTA;
      } else {
        db.prepare(`INSERT INTO subscriptions(user_id, plan_id, quota_bytes, expires_at, updated_at) VALUES (?, ?, ?, ?, ?)
          ON CONFLICT(user_id) DO UPDATE SET plan_id = excluded.plan_id, quota_bytes = excluded.quota_bytes,
          expires_at = excluded.expires_at, updated_at = excluded.updated_at`)
          .run(order.user_id, order.plan_id, plan.quota, expiresAt, now);
        const addonQuota = db.prepare(`SELECT COALESCE(SUM(quota_bytes), 0) AS total
          FROM storage_addons WHERE user_id = ? AND expires_at > ?`).get(order.user_id, now);
        effectiveQuota = Number(plan.quota) + Number(addonQuota.total);
      }
      const used = Number(q.usage.get(order.user_id).bytes);
      const account = q.userById.get(order.user_id);
      const overageSince = used > effectiveQuota
        ? Number(account?.storage_overage_since) || now
        : null;
      db.prepare('UPDATE users SET quota_bytes = ?, storage_overage_since = ? WHERE id = ?')
        .run(effectiveQuota, overageSince, order.user_id);
      activated = true;
    })();
    const member = q.userById.get(order.user_id);
    if (activated && member?.email) {
      const message = orderType === 'addon'
        ? { subject: 'Yuni Share · Additional Storage Activated', text: `Your ${plan.name} monthly storage add-on is active. Your total encrypted storage quota is now ${Math.round(effectiveQuota / 1024 ** 3)} GB. The additional storage is active until ${formatUtcTime(expiresAt)} and requires an active Yuni Share membership.` }
        : { subject: 'Yuni Share · Membership Activated', text: `Your ${plan.name} membership is active. Your encrypted storage quota is now ${Math.round(effectiveQuota / 1024 ** 3)} GB and the subscription is active until ${formatUtcTime(expiresAt)}.` };
      void transactionalMailRequest({ to: member.email, ...message }).catch(() => {});
    }
  }
  res.type('text').send('success');
});

app.get('/api/plans', (req, res) => res.json({
  free: { name: 'Free', quota: USER_QUOTA },
  plans: PLANS,
  storageAddons: STORAGE_ADDONS,
  paymentEnabled: PAYMENT_ENABLED
}));

app.get('/api/subscription', requireAuth, (req, res) => {
  const entitlements = refreshUserEntitlements(req.user.id);
  const user = entitlements.changed ? q.userById.get(req.user.id) : req.user;
  res.json({
    subscription: entitlements.subscription || { plan_id: 'free', quota_bytes: USER_QUOTA, expires_at: null },
    storageAddons: entitlements.addons,
    totalQuotaBytes: user.quota_bytes,
    paymentEnabled: PAYMENT_ENABLED
  });
});

app.post('/api/payment-orders', requireAuth, async (req, res, next) => {
  try {
    if (!PAYMENT_ENABLED) return jsonError(res, 503, '支付服务尚未配置');
    const now = Date.now();
    const orderType = String(req.body.orderType || 'subscription');
    const planId = String(req.body.planId || '');
    const billingCycle = String(req.body.billingCycle || 'monthly');
    const entitlements = refreshUserEntitlements(req.user.id, now);
    const activeSubscription = entitlements.subscription && Number(entitlements.subscription.expires_at) > now;
    let plan;
    let amountCents;
    if (orderType === 'subscription') {
      plan = PLANS[planId];
      if (!plan || !['monthly', 'yearly'].includes(billingCycle)) return jsonError(res, 400, '套餐或周期无效');
      if (activeSubscription) return jsonError(res, 409, '当前会员仍在有效期内，不能重复购买或延长。空间不足时请购买独立扩容包。');
      amountCents = plan[billingCycle];
    } else if (orderType === 'addon') {
      plan = STORAGE_ADDONS[planId];
      if (!plan || billingCycle !== 'monthly') return jsonError(res, 400, '扩容包无效');
      if (!activeSubscription) return jsonError(res, 409, '独立扩容包仅向有效会员开放，请先订阅基础会员。');
      amountCents = plan.monthly;
    } else {
      return jsonError(res, 400, '购买类型无效');
    }
    db.prepare(`UPDATE payment_orders SET status = 'expired'
      WHERE user_id = ? AND order_type = ? AND status = 'pending'`)
      .run(req.user.id, orderType);
    const orderNo = `YS${Date.now().toString(36)}${crypto.randomBytes(5).toString('hex')}`.toUpperCase();
    const notifyUrl = `${PUBLIC_URL}/api/payments/zhifux/notify`;
    const amount = (amountCents / 100).toFixed(2);
    db.prepare(`INSERT INTO payment_orders(order_no, user_id, plan_id, billing_cycle, amount_cents, status, created_at, order_type)
      VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)`).run(orderNo, req.user.id, planId, billingCycle, amountCents, now, orderType);
    const params = new URLSearchParams({ merchantNum: PAYMENT_MERCHANT_NUM, orderNo, amount, notifyUrl,
      returnUrl: `${PUBLIC_URL}/?payment=return`, payType: PAYMENT_PAY_TYPE,
      subject: orderType === 'addon' ? `Yuni Share ${plan.name} 月度扩容包` : `Yuni Share ${plan.name} ${billingCycle === 'yearly' ? '年订阅' : '月订阅'}`,
      sign: paymentSignature(`${PAYMENT_MERCHANT_NUM}${orderNo}${amount}${notifyUrl}${PAYMENT_SECRET}`), returnType: 'json' });
    const response = await fetch(`${PAYMENT_API_ROOT}/startOrder?${params}`, { method: 'POST' });
    const result = await response.json().catch(() => null);
    const payUrl = secureExternalUrl(result?.data?.payUrl);
    if (!response.ok || !result?.success || !payUrl) throw new Error(result?.msg || '创建支付订单失败');
    db.prepare('UPDATE payment_orders SET pay_url = ? WHERE order_no = ?').run(payUrl, orderNo);
    res.status(201).json({ orderNo, payUrl, expiresInMinutes: 15, orderType });
  } catch (error) { next(error); }
});

app.get('/api/payment-orders/:orderNo', requireAuth, (req, res) => {
  const order = db.prepare('SELECT order_no, status FROM payment_orders WHERE order_no = ? AND user_id = ?').get(req.params.orderNo, req.user.id);
  if (!order) return jsonError(res, 404, '支付订单不存在');
  res.json({ orderNo: order.order_no, status: order.status });
});

app.post('/api/profile/avatar', requireAuth, async (req, res, next) => {
  try {
    const source = String(req.body.dataUrl || '');
    const matched = /^data:(image\/(?:png|jpeg|webp));base64,([A-Za-z0-9+/=]+)$/.exec(source);
    if (!matched) return jsonError(res, 400, '头像仅支持 PNG、JPEG 或 WebP 图片');
    const bytes = Buffer.from(matched[2], 'base64');
    if (bytes.length < 32) return jsonError(res, 400, '头像文件无效');
    const extension = matched[1] === 'image/jpeg' ? 'jpg' : matched[1].slice(6);
    const filename = `${req.user.id}-${crypto.randomUUID()}.${extension}`;
    await fsp.writeFile(path.join(AVATAR_ROOT, filename), bytes, { mode: 0o600 });
    const previous = req.user.avatar_path;
    db.prepare('UPDATE users SET avatar_path = ? WHERE id = ?').run(filename, req.user.id);
    if (previous) await fsp.rm(path.join(AVATAR_ROOT, path.basename(previous)), { force: true }).catch(() => {});
    res.status(201).json({ avatarUrl: `/avatars/${filename}` });
  } catch (error) { next(error); }
});

app.patch('/api/profile/username', requireAuth, (req, res) => {
  const username = String(req.body.username || '').trim();
  if (!validUsername(username)) return jsonError(res, 400, '用户名需为 3-32 位字母、数字或下划线');
  db.prepare('UPDATE users SET username = ? WHERE id = ?').run(username, req.user.id);
  res.json({ok:true,username});
});
app.get('/api/me', requireAuth, (req, res) => {
  const used = q.usage.get(req.user.id).bytes;
  const overageSince = Number(req.user.storage_overage_since) || null;
  const encryption = req.user.encryption_version === ENCRYPTION_VERSION ? {
    version: req.user.encryption_version,
    salt: req.user.vault_salt,
    iv: req.user.vault_key_iv,
    wrappedKey: req.user.vault_wrapped_key,
    iterations: req.user.vault_kdf_iterations,
    recovery: req.user.vault_recovery_salt && req.user.vault_recovery_iv
      && req.user.vault_recovery_wrapped_key && req.user.vault_recovery_kdf_iterations ? {
      version: ENCRYPTION_VERSION,
      salt: req.user.vault_recovery_salt,
      iv: req.user.vault_recovery_iv,
      wrappedKey: req.user.vault_recovery_wrapped_key,
      iterations: req.user.vault_recovery_kdf_iterations
    } : null,
    passkeys: q.listActiveVaultPasskeys.all(req.user.id).map(passkeyClientSummary)
  } : null;
  const storageRetention = overageSince ? {
    active: true,
    startedAt: overageSince,
    deadlineAt: overageSince + PAID_STORAGE_GRACE_MS,
    excessBytes: Math.max(0, Number(used) - Number(req.user.quota_bytes)),
    uploadBlocked: Number(used) >= Number(req.user.quota_bytes)
  } : null;
  res.json({ accountId: req.user.public_id, email: req.user.email, username: req.user.username, avatarUrl: req.user.avatar_path ? `/avatars/${req.user.avatar_path}` : '', quota: req.user.quota_bytes, used, inviteRequired: Boolean(INVITE_REGISTRATION_ENABLED && INVITE_CODE), encryption, storageRetention });
});

app.get('/api/files', requireAuth, (req, res) => {
  res.json({
    files: q.listFiles.all(req.user.id),
    folders: q.listEncryptedFolders.all(req.user.id)
  });
});

app.post('/api/folders', requireAuth, (req, res) => {
  const id = String(req.body.id || '');
  if (!validUploadId(id)) return jsonError(res, 400, '文件夹编号无效');
  const encryption = uploadEncryption(req.body.encryption);
  const isRoot = req.body.isRoot === true ? 1 : 0;
  if (!encryption || req.user.encryption_version !== ENCRYPTION_VERSION) {
    return jsonError(res, 409, '请先在当前客户端解锁端到端加密空间');
  }
  const existing = q.encryptedFolder.get(id, req.user.id);
  if (existing) {
    if (existing.encrypted_metadata !== encryption.metadata
      || existing.encrypted_metadata_iv !== encryption.metadataIv) {
      return jsonError(res, 409, '文件夹编号已被占用');
    }
    q.updateEncryptedFolderHint.run(isRoot, Date.now(), id, req.user.id);
    return res.json({ id, reused: true });
  }
  const now = Date.now();
  q.insertEncryptedFolder.run(
    id,
    req.user.id,
    encryption.metadata,
    encryption.metadataIv,
    isRoot,
    now,
    now
  );
  res.status(201).json({ id });
});

app.patch('/api/folders/:id', requireAuth, (req, res) => {
  if (!validUploadId(req.params.id)) return jsonError(res, 400, '文件夹编号无效');
  const encryption = uploadEncryption(req.body.encryption);
  const isRoot = req.body.isRoot === true ? 1 : 0;
  if (!encryption || req.user.encryption_version !== ENCRYPTION_VERSION) {
    return jsonError(res, 409, '请先在当前客户端解锁端到端加密空间');
  }
  const updated = q.updateEncryptedFolderMetadata.run(
    encryption.metadata,
    encryption.metadataIv,
    isRoot,
    Date.now(),
    req.params.id,
    req.user.id
  );
  if (!updated.changes) return jsonError(res, 404, '文件夹不存在或无法更新');
  res.json({ ok: true });
});

app.post('/api/folders/batch-delete', requireAuth, (req, res) => {
  const ids = [...new Set(Array.isArray(req.body.ids) ? req.body.ids.map(String) : [])];
  if (!ids.length || ids.length > 500) {
    return jsonError(res, 400, '文件夹编号无效');
  }
  const deleteStmt = db.prepare('DELETE FROM encrypted_folders WHERE id = ? AND user_id = ?');
  db.transaction(() => {
    for (const id of ids) {
      deleteStmt.run(id, req.user.id);
    }
  })();
  res.json({ ok: true, deleted: ids });
});

app.delete('/api/folders/:id', requireAuth, (req, res) => {
  if (!validUploadId(req.params.id)) return jsonError(res, 400, '文件夹编号无效');
  q.deleteEncryptedFolder.run(req.params.id, req.user.id);
  res.json({ ok: true });
});

app.post('/api/files/listing-hints', requireAuth, (req, res) => {
  const hints = Array.isArray(req.body.hints) ? req.body.hints : [];
  if (hints.length > 1000) return jsonError(res, 400, '文件分类同步数量过多');
  let updated = 0;
  db.transaction(() => {
    for (const item of hints) {
      const id = String(item?.id || '');
      if (!validUploadId(id)) continue;
      const hint = listingHint(item);
      updated += q.updateFileListingHint.run(hint.category, hint.insideFolder, id, req.user.id).changes;
    }
  })();
  res.json({ ok: true, updated });
});

app.get('/api/uploads', requireAuth, async (req, res, next) => {
  try {
    const uploads = await Promise.all(q.listUploads.all(req.user.id).map(async upload => {
      const names = await fsp.readdir(path.join(TEMP_ROOT, upload.id)).catch(() => []);
      if (upload.logical_size !== null && upload.logical_size !== undefined) {
        const recorded = recordedUploadChunkSizes(upload) || [];
        const completedChunks = recorded.filter((size) => Number.isSafeInteger(size) && size > 0).length;
        const uploadedBytes = completedChunks >= upload.chunk_count
          ? Number(upload.logical_size)
          : Math.min(Number(upload.logical_size), completedChunks * Number(upload.chunk_size));
        return { ...upload, uploaded_bytes: uploadedBytes };
      }
      const completed = names.reduce((bytes, name) => {
        const index = Number(name);
        if (!Number.isInteger(index) || String(index) !== name || index < 0 || index >= upload.chunk_count) return bytes;
        const chunkBytes = index === upload.chunk_count - 1
          ? upload.size - upload.chunk_size * index
          : upload.chunk_size;
        return bytes + chunkBytes;
      }, 0);
      return { ...upload, uploaded_bytes: Math.min(upload.size, completed) };
    }));
    res.json({ uploads });
  } catch (error) {
    next(error);
  }
});

app.post('/api/uploads', requireAuth, async (req, res) => {
  const requestedId = String(req.body.id || '');
  if (requestedId && !validUploadId(requestedId)) return jsonError(res, 400, '上传任务编号无效');
  const id = requestedId || crypto.randomUUID();
  const encryption = uploadEncryption(req.body.encryption);
  const hint = listingHint(req.body.listingHint);
  if (!encryption || req.user.encryption_version !== ENCRYPTION_VERSION) {
    return jsonError(res, 409, '请先在当前客户端解锁端到端加密空间后再上传');
  }
  // Names, paths, types, per-file keys and original sizes are inside encrypted
  // metadata. Only a fixed placeholder is stored in legacy NOT NULL columns.
  const name = 'Encrypted file';
  const size = Number(req.body.size);
  const logicalSize = req.body.logicalSize === undefined ? null : Number(req.body.logicalSize);
  const compressedUpload = req.body.compressionVersion === 1;
  const mime = 'application/octet-stream';
  if (compressedUpload && (!Number.isSafeInteger(logicalSize) || logicalSize < 0)) {
    return jsonError(res, 400, '原始文件大小无效');
  }
  const existingUpload = q.upload.get(id, req.user.id);
  if (existingUpload) {
    if (existingUpload.original_name !== name || existingUpload.size !== size || existingUpload.mime_type !== mime
      || (compressedUpload && existingUpload.logical_size !== logicalSize)
      || existingUpload.encryption_version !== encryption.version
      || existingUpload.encrypted_metadata !== encryption.metadata
      || existingUpload.encrypted_metadata_iv !== encryption.metadataIv
      || existingUpload.listing_category !== hint.category
      || existingUpload.inside_folder !== hint.insideFolder) {
      return jsonError(res, 409, '上传任务编号已被其他文件使用');
    }
    q.touchUpload.run(Date.now(), id, req.user.id);
    return res.json({
      id,
      chunkSize: existingUpload.chunk_size,
      chunkCount: existingUpload.chunk_count,
      resumed: true
    });
  }
  if (isUploadCancelled(req.user.id, id)) return jsonError(res, 409, '上传已取消');
  if (!Number.isSafeInteger(size) || size < 0) return jsonError(res, 400, '文件大小无效');
  const chunkCount = compressedUpload
    ? Math.max(1, Math.ceil(logicalSize / CHUNK_SIZE))
    : Math.max(1, Math.ceil(size / CHUNK_SIZE));
  if (compressedUpload && size !== logicalSize + chunkCount * (GCM_TAG_BYTES + 1)) {
    return jsonError(res, 400, '压缩上传大小参数无效');
  }
  const plainSize = compressedUpload
    ? logicalSize
    : Math.max(0, size - chunkCount * GCM_TAG_BYTES);
  const used = q.usage.get(req.user.id).bytes;
  const reserved = q.reserved.get(req.user.id).bytes;
  if (used + reserved + plainSize > req.user.quota_bytes) return jsonError(res, 413, '账户空间不足');
  const disk = STORAGE_ENABLED ? null : await fsp.statfs(DATA_ROOT);
  if (isUploadCancelled(req.user.id, id)) return jsonError(res, 409, '上传已取消');
  if (disk && disk.bavail * disk.bsize - size < DISK_RESERVE) return jsonError(res, 507, '服务器可用空间不足');
  try {
    if (STORAGE_ENABLED) await storageRequest('/internal/share/objects', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id, size, chunkCount, elasticSize: compressedUpload, poolId: STORAGE_POOL_ID })
    });
    db.prepare(`INSERT INTO uploads(
      id, user_id, original_name, mime_type, size, logical_size, chunk_sizes_json, received_size,
      chunk_size, chunk_count, created_at,
      encryption_version, encrypted_metadata, encrypted_metadata_iv, storage_object_id,
      listing_category, inside_folder
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`) 
      .run(id, req.user.id, name, mime, size, compressedUpload ? logicalSize : null, null, 0,
        CHUNK_SIZE, chunkCount, Date.now(),
        encryption.version, encryption.metadata, encryption.metadataIv, STORAGE_ENABLED ? id : null,
        hint.category, hint.insideFolder);
    if (!STORAGE_ENABLED) await fsp.mkdir(path.join(TEMP_ROOT, id), { recursive: true });
    if (isUploadCancelled(req.user.id, id)) {
      const upload = q.upload.get(id, req.user.id);
      if (upload) await removeUpload(upload);
      return jsonError(res, 409, '上传已取消');
    }
    res.status(201).json({ id, chunkSize: CHUNK_SIZE, chunkCount });
  } catch (error) {
    const upload = q.upload.get(id, req.user.id);
    if (upload) await removeUpload(upload);
    if (error.code === 'SQLITE_CONSTRAINT_PRIMARYKEY') return jsonError(res, 409, '上传任务已存在');
    throw error;
  }
});

app.put('/api/uploads/:id/chunks/:index', requireAuth, async (req, res) => {
  if (!validUploadId(req.params.id)) return jsonError(res, 400, '上传任务编号无效');
  if (isUploadCancelled(req.user.id, req.params.id)) return jsonError(res, 410, '上传已取消');
  const upload = q.upload.get(req.params.id, req.user.id);
  if (!upload) return jsonError(res, 404, '上传任务不存在或已过期');
  const index = Number(req.params.index);
  if (!Number.isInteger(index) || index < 0 || index >= upload.chunk_count) return jsonError(res, 400, '分片编号无效');
  const variableChunks = upload.logical_size !== null && upload.logical_size !== undefined;
  const expected = index === upload.chunk_count - 1 ? upload.size - upload.chunk_size * index : upload.chunk_size;
  const contentLength = Number(req.get('content-length'));
  const maxVariableChunk = Number(upload.chunk_size) + GCM_TAG_BYTES + 1;
  if (!Number.isSafeInteger(contentLength)
    || (variableChunks
      ? contentLength < GCM_TAG_BYTES + 1 || contentLength > maxVariableChunk
      : contentLength !== expected)) return jsonError(res, 400, '分片大小不正确');

  if (STORAGE_ENABLED && upload.storage_object_id) {
    await storageRequest(`/internal/share/objects/${encodeURIComponent(upload.storage_object_id)}/chunks/${index}`, {
      method: 'PUT', headers: { 'Content-Type': 'application/octet-stream', 'Content-Length': String(contentLength) }, body: req
    });
    recordUploadChunk(upload.id, req.user.id, index, contentLength);
    return res.json({ ok: true });
  }

  const chunkPath = path.join(TEMP_ROOT, upload.id, String(index));
  const existing = await fsp.stat(chunkPath).catch(() => null);
  if (existing && ((!variableChunks && existing.size === expected)
    || (variableChunks && existing.size >= GCM_TAG_BYTES + 1 && existing.size <= maxVariableChunk))) {
    recordUploadChunk(upload.id, req.user.id, index, existing.size);
    return res.json({ ok: true, reused: true });
  }
  if (existing) await fsp.rm(chunkPath, { force: true });

  // Stream directly to disk instead of buffering the whole chunk in memory.
  // A temporary name prevents an interrupted request from looking complete.
  const tempPath = `${chunkPath}.${crypto.randomUUID()}.part`;
  try {
    await pipeline(req, fs.createWriteStream(tempPath, { flags: 'wx', mode: 0o600 }));
    const info = await fsp.stat(tempPath).catch(() => null);
    if (!info || (!variableChunks && info.size !== expected)
      || (variableChunks && (info.size < GCM_TAG_BYTES + 1 || info.size > maxVariableChunk))) {
      await fsp.rm(tempPath, { force: true });
      return jsonError(res, 400, '分片大小不正确');
    }
    if (isUploadCancelled(req.user.id, upload.id)) {
      await fsp.rm(tempPath, { force: true });
      return jsonError(res, 410, '上传已取消');
    }
    await fsp.rename(tempPath, chunkPath);
    recordUploadChunk(upload.id, req.user.id, index, info.size);
    res.json({ ok: true });
  } catch (error) {
    await fsp.rm(tempPath, { force: true }).catch(() => {});
    if (req.aborted || res.destroyed) return;
    if (isUploadCancelled(req.user.id, upload.id)) return jsonError(res, 410, '上传已取消');
    throw error;
  }
});

app.post('/api/uploads/:id/complete', requireAuth, async (req, res) => {
  if (!validUploadId(req.params.id)) return jsonError(res, 400, '上传任务编号无效');
  const completedFile = q.fileByUpload.get(req.params.id, req.user.id);
  if (completedFile) return res.json({ id: completedFile.id, reused: true });
  if (isUploadCancelled(req.user.id, req.params.id)) return jsonError(res, 410, '上传已取消');
  const upload = q.upload.get(req.params.id, req.user.id);
  if (!upload) return jsonError(res, 404, '上传任务不存在或已过期');
  const variableChunks = upload.logical_size !== null && upload.logical_size !== undefined;
  const recordedSizes = recordedUploadChunkSizes(upload);
  let chunkSizes = variableChunks ? recordedSizes : uploadChunkSizes(upload);
  if (variableChunks && STORAGE_ENABLED && upload.storage_object_id) {
    // The Storage service is the source of truth for bytes that were accepted.
    // A client connection can disappear after Storage commits a part but before
    // this process records the acknowledgement in Share's SQLite database.
    const storageSizes = await storageUploadChunkSizes(upload).catch(() => null);
    if (storageSizes) {
      chunkSizes = storageSizes;
      const received = storageSizes.reduce((sum, size) => sum + size, 0);
      db.prepare(`UPDATE uploads SET chunk_sizes_json = ?, received_size = ?, created_at = ?
        WHERE id = ? AND user_id = ?`).run(JSON.stringify(storageSizes), received, Date.now(), upload.id, req.user.id);
    }
  }
  if (!chunkSizes || chunkSizes.length !== Number(upload.chunk_count)
    || !chunkSizes.every((size) => Number.isSafeInteger(size) && size > 0)) {
    return jsonError(res, 409, '仍有加密分片未上传完成');
  }
  const storedSize = chunkSizes.reduce((sum, size) => sum + size, 0);
  const key = uploadKey(req.user.id, upload.id);
  const completion = { cancelled: false, output: null, fileId: null, finalPath: null };
  completingUploads.set(key, completion);
  const dir = path.join(TEMP_ROOT, upload.id);
  const fileId = crypto.randomUUID();
  const storedName = `${fileId}.bin`;
  const userDir = path.join(FILE_ROOT, String(req.user.id));
  const finalPath = path.join(userDir, storedName);
  completion.fileId = fileId;
  completion.finalPath = finalPath;
  if (STORAGE_ENABLED && upload.storage_object_id) {
    let storageCompleted = false;
    try {
      await storageRequest(`/internal/share/objects/${encodeURIComponent(upload.storage_object_id)}/complete`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(variableChunks ? { size: storedSize } : {})
      });
      storageCompleted = true;
      db.transaction(() => {
        const used = q.usage.get(req.user.id).bytes;
        const plainSize = plainStoredFileSize(upload);
        if (used + plainSize > req.user.quota_bytes) throw new Error('QUOTA_EXCEEDED');
        db.prepare(`INSERT INTO files(id, user_id, upload_id, original_name, stored_name, mime_type, size, logical_size, chunk_sizes_json, created_at,
          encryption_version, encrypted_metadata, encrypted_metadata_iv, chunk_size, chunk_count, storage_object_id,
          listing_category, inside_folder)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
          .run(fileId, req.user.id, upload.id, upload.original_name, storedName, upload.mime_type, storedSize,
            variableChunks ? upload.logical_size : null, JSON.stringify(chunkSizes), Date.now(),
            upload.encryption_version, upload.encrypted_metadata, upload.encrypted_metadata_iv, upload.chunk_size, upload.chunk_count,
            upload.storage_object_id, upload.listing_category, upload.inside_folder);
        db.prepare('DELETE FROM uploads WHERE id = ?').run(upload.id);
      })();
      return res.status(201).json({ id: fileId });
    } catch (error) {
      if (storageCompleted) {
        await storageRequest(`/internal/share/objects/${encodeURIComponent(upload.storage_object_id)}`, { method: 'DELETE' }).catch(() => {});
      }
      throw error;
    } finally { completingUploads.delete(key); }
  }
  let output;
  try {
    for (let i = 0; i < upload.chunk_count; i += 1) {
      const info = await fsp.stat(path.join(dir, String(i))).catch(() => null);
       const expected = variableChunks ? chunkSizes[i]
         : (i === upload.chunk_count - 1 ? upload.size - upload.chunk_size * i : upload.chunk_size);
       if (!info || info.size !== expected) return jsonError(res, 409, '仍有分片未上传完成');
    }
    if (completion.cancelled || isUploadCancelled(req.user.id, upload.id)) throw uploadCancelledError();
    await fsp.mkdir(userDir, { recursive: true });
    output = fs.createWriteStream(finalPath, { flags: 'wx', mode: 0o600 });
    completion.output = output;
    const assembledFile = Readable.from((async function* assembleChunks() {
      for (let i = 0; i < upload.chunk_count; i += 1) {
        if (completion.cancelled || isUploadCancelled(req.user.id, upload.id)) throw uploadCancelledError();
        for await (const data of fs.createReadStream(path.join(dir, String(i)))) {
          if (completion.cancelled || isUploadCancelled(req.user.id, upload.id)) throw uploadCancelledError();
          yield data;
        }
      }
    })());
    await pipeline(assembledFile, output);
    db.transaction(() => {
      if (completion.cancelled || isUploadCancelled(req.user.id, upload.id) || !q.upload.get(upload.id, req.user.id)) {
        throw uploadCancelledError();
      }
       const used = q.usage.get(req.user.id).bytes;
       const plainSize = plainStoredFileSize(upload);
       if (used + plainSize > req.user.quota_bytes) throw new Error('QUOTA_EXCEEDED');
       db.prepare(`INSERT INTO files(
        id, user_id, upload_id, original_name, stored_name, mime_type, size, logical_size, chunk_sizes_json, created_at,
        encryption_version, encrypted_metadata, encrypted_metadata_iv, chunk_size, chunk_count,
        listing_category, inside_folder
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`) 
        .run(fileId, req.user.id, upload.id, upload.original_name, storedName, upload.mime_type, storedSize,
          variableChunks ? upload.logical_size : null, JSON.stringify(chunkSizes), Date.now(),
          upload.encryption_version, upload.encrypted_metadata, upload.encrypted_metadata_iv, upload.chunk_size, upload.chunk_count,
          upload.listing_category, upload.inside_folder);
      db.prepare('DELETE FROM uploads WHERE id = ?').run(upload.id);
    })();
    await fsp.rm(dir, { recursive: true, force: true });
    if (completion.cancelled || isUploadCancelled(req.user.id, upload.id)) throw uploadCancelledError();
    res.status(201).json({ id: fileId });
  } catch (error) {
    output?.destroy();
    db.prepare('DELETE FROM files WHERE id = ? AND user_id = ?').run(fileId, req.user.id);
    await fsp.rm(finalPath, { force: true });
    if (error.code === 'UPLOAD_CANCELLED' || error.message === 'UPLOAD_CANCELLED') return jsonError(res, 409, '上传已取消');
    if (error.message === 'QUOTA_EXCEEDED') return jsonError(res, 413, '账户空间不足');
    throw error;
  } finally {
    completingUploads.delete(key);
  }
});

app.delete('/api/uploads/:id', requireAuth, async (req, res) => {
  if (!validUploadId(req.params.id)) return jsonError(res, 400, '上传任务编号无效');
  markUploadCancelled(req.user.id, req.params.id);
  const completion = completingUploads.get(uploadKey(req.user.id, req.params.id));
  if (completion) {
    completion.cancelled = true;
    completion.output?.destroy();
    if (completion.fileId) db.prepare('DELETE FROM files WHERE id = ? AND user_id = ?').run(completion.fileId, req.user.id);
    if (completion.finalPath) await fsp.rm(completion.finalPath, { force: true });
  }
  const upload = q.upload.get(req.params.id, req.user.id);
  if (upload) await removeUpload(upload);
  else await fsp.rm(path.join(TEMP_ROOT, req.params.id), { recursive: true, force: true });
  const completedFile = q.fileByUpload.get(req.params.id, req.user.id);
  if (completedFile) {
    db.prepare('DELETE FROM files WHERE id = ? AND user_id = ?').run(completedFile.id, req.user.id);
    await fsp.rm(path.join(FILE_ROOT, String(req.user.id), completedFile.stored_name), { force: true });
  }
  res.json({ ok: true });
});

app.get('/api/files/:id/download', requireAuth, (req, res, next) => {
  const file = q.file.get(req.params.id, req.user.id);
  if (!file) return jsonError(res, 404, '文件不存在');
  return jsonError(res, 410, '文件须在受支持客户端中解密后下载');
});

app.put('/api/files/:id/content', requireAuth, async (req, res) => {
  const file = q.file.get(req.params.id, req.user.id);
  if (!file) return jsonError(res, 404, '文件不存在');
  const uploadId = String(req.body.uploadId || '');
  if (!validUploadId(uploadId)) return jsonError(res, 400, '文件编号无效');
  const encryption = uploadEncryption(req.body.encryption);
  if (!encryption || req.user.encryption_version !== ENCRYPTION_VERSION) {
    return jsonError(res, 409, '请先在当前客户端解锁端到端加密空间');
  }
  const hint = listingHint(req.body);
  const size = Math.max(0, Number(req.body.size || 0));
  const chunkCount = Math.max(0, Number(req.body.chunkCount || 0));
  const encryptedChunkBase64 = String(req.body.encryptedChunk || '');

  try {
    if (STORAGE_ENABLED) {
      if (file.storage_object_id) {
        await storageRequest(`/internal/share/objects/${encodeURIComponent(file.storage_object_id)}`, { method: 'DELETE' }).catch(() => {});
      }
      if (chunkCount > 0 && encryptedChunkBase64) {
        await storageRequest('/internal/share/objects', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id: uploadId, size, chunkCount, poolId: STORAGE_POOL_ID })
        });
        const chunkBuf = Buffer.from(encryptedChunkBase64, 'base64');
        await storageRequest(`/internal/share/objects/${encodeURIComponent(uploadId)}/chunks/0`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/octet-stream' },
          body: chunkBuf
        });
        await storageRequest(`/internal/share/objects/${encodeURIComponent(uploadId)}/complete`, {
          method: 'POST'
        }).catch(() => {});
      }
    } else {
      const userDir = path.join(FILE_ROOT, String(req.user.id));
      await fsp.mkdir(userDir, { recursive: true });
      const chunkBuf = chunkCount > 0 && encryptedChunkBase64 ? Buffer.from(encryptedChunkBase64, 'base64') : Buffer.alloc(0);
      await fsp.writeFile(path.join(userDir, file.stored_name), chunkBuf, { mode: 0o600 });
    }

    db.prepare(`UPDATE files SET
      upload_id = ?,
      size = ?,
      logical_size = ?,
      chunk_sizes_json = ?,
      chunk_size = ?,
      chunk_count = ?,
      storage_object_id = ?,
      encrypted_metadata = ?,
      encrypted_metadata_iv = ?,
      listing_category = ?
      WHERE id = ? AND user_id = ?`).run(
      uploadId, size, size > 0 ? Math.max(0, size - GCM_TAG_BYTES) : 0, chunkCount > 0 ? JSON.stringify([size]) : null,
      CHUNK_SIZE, chunkCount, (STORAGE_ENABLED && chunkCount > 0) ? uploadId : null,
      encryption.metadata, encryption.metadataIv, hint.category,
      file.id, req.user.id
    );

    res.json({ id: file.id, ok: true });
  } catch (error) {
    console.error('Error updating file content:', error);
    jsonError(res, 500, '更新文件内容失败');
  }
});

app.post('/api/files/empty', requireAuth, async (req, res) => {
  const uploadId = String(req.body.uploadId || '');
  if (!validUploadId(uploadId)) return jsonError(res, 400, '文件编号无效');
  const encryption = uploadEncryption(req.body.encryption);
  if (!encryption || req.user.encryption_version !== ENCRYPTION_VERSION) {
    return jsonError(res, 409, '请先在当前客户端解锁端到端加密空间');
  }
  const hint = listingHint(req.body);
  const fileId = crypto.randomUUID();
  const storedName = `${fileId}.bin`;
  const now = Date.now();

  try {
    if (STORAGE_ENABLED) {
      await storageRequest('/internal/share/objects', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: uploadId, size: 0, chunkCount: 0, poolId: STORAGE_POOL_ID })
      }).catch(() => {});
      await storageRequest(`/internal/share/objects/${encodeURIComponent(uploadId)}/complete`, {
        method: 'POST'
      }).catch(() => {});
    } else {
      const userDir = path.join(FILE_ROOT, String(req.user.id));
      await fsp.mkdir(userDir, { recursive: true });
      await fsp.writeFile(path.join(userDir, storedName), Buffer.alloc(0), { mode: 0o600 });
    }

    db.prepare(`INSERT INTO files(
      id, user_id, upload_id, original_name, stored_name, mime_type, size, logical_size, chunk_sizes_json, created_at,
      encryption_version, encrypted_metadata, encrypted_metadata_iv, chunk_size, chunk_count,
      storage_object_id, listing_category, inside_folder
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      fileId, req.user.id, uploadId, 'encrypted', storedName, 'application/octet-stream', 0, 0, null, now,
      encryption.version, encryption.metadata, encryption.metadataIv, CHUNK_SIZE, 0,
      STORAGE_ENABLED ? uploadId : null, hint.category, hint.insideFolder
    );

    res.status(201).json({ id: fileId, ok: true });
  } catch (error) {
    console.error('Error creating empty file:', error);
    res.status(500).json({ error: '创建空文件失败' });
  }
});

app.post('/api/files/batch-metadata', requireAuth, (req, res) => {
  const updates = Array.isArray(req.body.updates) ? req.body.updates : [];
  if (!updates.length) return res.json({ ok: true, count: 0 });
  if (req.user.encryption_version !== ENCRYPTION_VERSION) {
    return jsonError(res, 409, '请先在当前客户端解锁端到端加密空间');
  }

  const updateStmt = q.updateFileMetadata;
  const updateMany = db.transaction((items) => {
    let count = 0;
    for (const item of items) {
      if (!validUploadId(item.id)) continue;
      const encryption = uploadEncryption(item.encryption);
      if (!encryption) continue;
      const r = updateStmt.run(encryption.metadata, encryption.metadataIv, item.id, req.user.id);
      if (r.changes) count += 1;
    }
    return count;
  });

  const updatedCount = updateMany(updates);
  res.json({ ok: true, count: updatedCount });
});

app.patch('/api/files/:id/metadata', requireAuth, (req, res) => {
  if (!validUploadId(req.params.id)) return jsonError(res, 400, '文件编号无效');
  const encryption = uploadEncryption(req.body.encryption);
  if (!encryption || req.user.encryption_version !== ENCRYPTION_VERSION) {
    return jsonError(res, 409, '请先在当前客户端解锁端到端加密空间');
  }
  // Folders are a client-side virtual hierarchy. Updating a name or path must
  // never move the backing storage object or its chunks between storage nodes.
  const updated = q.updateFileMetadata.run(
    encryption.metadata,
    encryption.metadataIv,
    req.params.id,
    req.user.id
  );
  if (!updated.changes) return jsonError(res, 404, '文件不存在或无法更新');
  res.json({ ok: true });
});

app.get('/api/files/:id/chunks/:index', requireAuth, async (req, res, next) => {
  const file = q.file.get(req.params.id, req.user.id);
  if (!file) return jsonError(res, 404, '文件不存在');
  if (file.encryption_version !== ENCRYPTION_VERSION || !Number.isSafeInteger(file.chunk_size) || file.chunk_size <= 0) {
    return jsonError(res, 409, '文件不是端到端加密文件');
  }
  const index = Number(req.params.index);
  const chunkCount = file.chunk_count || Math.max(1, Math.ceil(file.size / file.chunk_size));
  if (!Number.isInteger(index) || index < 0 || index >= chunkCount) return jsonError(res, 400, '分片编号无效');
  const chunkSizes = fileChunkSizes(file);
  if (!chunkSizes) return jsonError(res, 409, '文件分片信息无效');
  const start = chunkSizes.slice(0, index).reduce((sum, size) => sum + size, 0);
  const length = chunkSizes[index];
  if (length <= 0) return jsonError(res, 409, '文件分片信息无效');
  if (STORAGE_ENABLED && file.storage_object_id) {
    try {
      const response = await storageRequest(`/internal/share/objects/${encodeURIComponent(file.storage_object_id)}/chunks/${index}`);
      res.set({ 'Content-Type': 'application/octet-stream', 'Content-Length': String(length), 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
      return Readable.fromWeb(response.body).on('error', next).pipe(res);
    } catch (error) { return next(error); }
  }
  const filePath = path.join(FILE_ROOT, String(req.user.id), file.stored_name);
  try {
    const info = await fsp.stat(filePath);
    if (info.size !== file.size) return jsonError(res, 409, '文件内容不完整');
    res.set({
      'Content-Type': 'application/octet-stream',
      'Content-Length': String(length),
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff'
    });
    fs.createReadStream(filePath, { start, end: start + length - 1 }).on('error', next).pipe(res);
  } catch (error) {
    next(error);
  }
});

app.post('/api/files/batch-delete', requireAuth, async (req, res) => {
  const ids = [...new Set(Array.isArray(req.body.ids) ? req.body.ids.map(String) : [])];
  if (!ids.length || ids.length > 500) {
    return jsonError(res, 400, '请选择 1 至 500 个有效文件');
  }
  const files = [];
  const failed = [];
  for (const id of ids) {
    const file = q.file.get(id, req.user.id);
    if (!file) {
      failed.push({ id, error: '文件不存在' });
    } else {
      files.push(file);
    }
  }

  if (files.length) {
    if (STORAGE_ENABLED) {
      const storageObjectIds = files.map(f => f.storage_object_id).filter(Boolean);
      if (storageObjectIds.length) {
        await storageRequest('/internal/share/objects/batch-delete', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ids: storageObjectIds })
        }).catch(err => console.error('Storage batch delete error:', err));
      }
    } else {
      await Promise.all(files.map(f => fsp.rm(path.join(FILE_ROOT, String(f.user_id), f.stored_name), { force: true })));
    }

    const deleteStmt = db.prepare('DELETE FROM files WHERE id = ? AND user_id = ?');
    db.transaction(() => {
      for (const file of files) {
        deleteStmt.run(file.id, file.user_id);
      }
    })();
  }

  const used = Number(q.usage.get(req.user.id).bytes);
  if (used <= Number(req.user.quota_bytes)) {
    db.prepare('UPDATE users SET storage_overage_since = NULL WHERE id = ?').run(req.user.id);
  }
  const deleted = files.map(f => f.id);
  res.status(200).json({ ok: true, deleted, failed });
});

app.delete('/api/files/:id', requireAuth, async (req, res) => {
  const file = q.file.get(req.params.id, req.user.id);
  if (!file) return jsonError(res, 404, '文件不存在');
  await removeStoredFile(file);
  if (Number(q.usage.get(req.user.id).bytes) <= Number(req.user.quota_bytes)) {
    db.prepare('UPDATE users SET storage_overage_since = NULL WHERE id = ?').run(req.user.id);
  }
  res.json({ ok: true });
});

app.get('/admin', (req, res) => res.sendFile(path.join(process.cwd(), 'public', 'admin.html')));
app.get('/admin.html', (req, res) => res.sendFile(path.join(process.cwd(), 'public', 'admin.html')));
app.get('/admin.js', (req, res) => res.sendFile(path.join(process.cwd(), 'public', 'admin.js')));
app.get('/admin.css', (req, res) => res.sendFile(path.join(process.cwd(), 'public', 'admin.css')));

app.get('/.well-known/assetlinks.json', (req, res) => {
  res.set({
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'public, max-age=3600, must-revalidate'
  });
  res.json([{
    relation: [
      'delegate_permission/common.handle_all_urls',
      'delegate_permission/common.get_login_creds'
    ],
    target: {
      namespace: 'android_app',
      package_name: 'xyz.yunishare.app',
      sha256_cert_fingerprints: [ANDROID_APP_CERT_SHA256]
    }
  }, {
    relation: [
      'delegate_permission/common.handle_all_urls',
      'delegate_permission/common.get_login_creds'
    ],
    target: {
      namespace: 'android_app',
      package_name: 'xyz.yunishare.native',
      sha256_cert_fingerprints: ['E3:85:38:A5:7E:89:00:92:36:D7:E2:BC:1E:FE:48:19:71:2F:96:A5:3A:B0:0D:DC:06:08:B2:5F:84:53:14:1A']
    }
  }]);
});

function renderLegalPage(content, activeKey) {
  const legalEntries = [...SITE_CONTENT_DEFINITIONS.entries()].filter(([, definition]) => definition.route);
  const navigation = legalEntries.map(([key, definition]) => `<a${key === activeKey ? ' class="active" aria-current="page"' : ''} href="${definition.route}">${escapeSiteHtml(definition.label)}</a>`).join('');
  const footer = legalEntries.map(([, definition]) => `<a href="${definition.route}">${escapeSiteHtml(definition.label)}</a>`).join('');
  return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeSiteHtml(content.title)} | YUNI Share</title><link rel="icon" type="image/png" href="/li-bai-avatar.png">
<link rel="stylesheet" href="/legal.css" integrity="sha384-Sr/otJwfVIMUagABD9DqqmjzP6LSeSYAcLIPwNhZkvKNrJlvjlAWnJ7MSJj5hryi" crossorigin="anonymous"></head>
<body><header class="topbar"><a class="brand" href="/"><img src="/li-bai-avatar.png" alt=""><span>YUNI Share</span></a><a class="back" href="/">返回文件空间</a></header>
<main><p class="eyebrow">YUNI Share</p><h1>${escapeSiteHtml(content.title)}</h1>
<p class="intro">${escapeSiteHtml(content.intro)}</p><p class="meta">${escapeSiteHtml(content.meta)}</p>
<nav class="legalnav" aria-label="政策页面切换">${navigation}</nav>${content.body_html || '<p>本页面内容正在更新。</p>'}</main>
<footer class="footer">${footer}</footer></body></html>`;
}

app.get('/api/site/announcement', (req, res) => {
  const row = db.prepare('SELECT title, intro, meta, body_html, enabled, updated_at FROM site_content WHERE content_key = ?').get('announcement');
  if (!row || Number(row.enabled) !== 1 || !row.body_html.trim()) return res.json({ enabled: false });
  res.json({ enabled: true, title: row.title, intro: row.intro, meta: row.meta, bodyHtml: row.body_html, updatedAt: row.updated_at });
});

for (const [key, definition] of SITE_CONTENT_DEFINITIONS) {
  if (!definition.route) continue;
  app.get(definition.route, (req, res) => {
    const content = db.prepare('SELECT title, intro, meta, body_html FROM site_content WHERE content_key = ?').get(key);
    if (!content) return res.sendFile(path.join(process.cwd(), 'public', definition.fileName));
    res.type('html').send(renderLegalPage(content, key));
  });
  const fileName = definition.fileName;
  app.get(`${definition.route}.html`, (req, res) => res.sendStatus(404));
}

const pdfJsRoot = path.join(process.cwd(), 'node_modules', 'pdfjs-dist');
app.use('/vendor/pdfjs/build', express.static(path.join(pdfJsRoot, 'build'), { immutable: true, maxAge: '1y' }));
app.use('/vendor/pdfjs/cmaps', express.static(path.join(pdfJsRoot, 'cmaps'), { immutable: true, maxAge: '1y' }));
app.use('/vendor/pdfjs/standard_fonts', express.static(path.join(pdfJsRoot, 'standard_fonts'), { immutable: true, maxAge: '1y' }));

app.get('/recovery-account', (req,res)=>{res.set('Cache-Control','no-store');res.sendFile(path.resolve('public/recovery-account.html'));});

app.use(express.static('public', {
  index: 'index.html',
  maxAge: '1h',
  setHeaders(res, filePath) {
    if (/\.(?:html|js|css)$/.test(filePath)) {
      res.set({
        'Cache-Control': 'no-store, no-cache, no-transform, must-revalidate, max-age=0',
        'CDN-Cache-Control': 'no-store',
        'Cloudflare-CDN-Cache-Control': 'no-store'
      });
    }
  }
}));
app.use('/api', (req, res) => jsonError(res, 404, '接口不存在'));
app.get('*path', (req, res) => {
  res.set({
    'Cache-Control': 'no-store, no-cache, no-transform, must-revalidate, max-age=0',
    'CDN-Cache-Control': 'no-store',
    'Cloudflare-CDN-Cache-Control': 'no-store'
  });
  res.sendFile(path.resolve('public/index.html'));
});
app.use((error, req, res, next) => {
  if (req.aborted || error?.type === 'request.aborted' || error?.code === 'ECONNABORTED') return;
  console.error(error);
  if (res.headersSent) return next(error);
  jsonError(res, 500, '服务器内部错误');
});

const server = app.listen(PORT, '0.0.0.0', () => console.log(`Yuni Share listening on ${PORT}`));
process.on('SIGTERM', () => server.close(() => { db.close(); process.exit(0); }));
