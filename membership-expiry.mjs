import crypto from 'node:crypto';

export const MEMBERSHIP_EXPIRY_REMINDER_MS = 3 * 24 * 60 * 60 * 1000;
export const PAID_STORAGE_RETENTION_MS = 15 * 24 * 60 * 60 * 1000;
export const MEMBERSHIP_EXPIRY_TEMPLATE = 'yuni-share-membership-expiry-v1';

const DEFAULT_FREE_QUOTA_BYTES = 5 * 1024 ** 3;
const DEFAULT_RETRY_MS = 15 * 60 * 1000;
const PLAN_LABELS = new Map([
  ['lite', 'Lite'],
  ['plus', 'Plus'],
  ['pro', 'Pro'],
  ['max', 'Max'],
  ['vault', 'Vault']
]);

function inlineText(value, fallback) {
  const normalized = String(value || '').replace(/[\r\n\t]+/g, ' ').trim();
  return normalized || fallback;
}

export function formatUtcTime(timestamp) {
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

export function formatStorage(bytes) {
  const value = Math.max(0, Number(bytes) || 0);
  if (value >= 1024 ** 4) return `${Number((value / 1024 ** 4).toFixed(1))} TB`;
  if (value >= 1024 ** 3) return `${Number((value / 1024 ** 3).toFixed(1))} GB`;
  if (value >= 1024 ** 2) return `${Number((value / 1024 ** 2).toFixed(1))} MB`;
  if (value >= 1024) return `${Number((value / 1024).toFixed(1))} KB`;
  return `${Math.round(value)} B`;
}

export function membershipExpiryReminderMessage({
  displayName = '',
  planId = '',
  planQuotaBytes,
  expiresAt,
  usedBytes,
  freeQuotaBytes = DEFAULT_FREE_QUOTA_BYTES,
  publicUrl
}) {
  const expiry = Number(expiresAt);
  const usage = Number(usedBytes);
  const planQuota = Number(planQuotaBytes);
  const freeQuota = Number(freeQuotaBytes);
  if (!Number.isFinite(expiry) || expiry <= 0) throw new TypeError('A valid membership expiration time is required.');
  if (!Number.isFinite(usage) || usage < 0) throw new TypeError('A valid current storage usage is required.');
  if (!Number.isFinite(planQuota) || planQuota <= 0) throw new TypeError('A valid membership quota is required.');
  if (!Number.isFinite(freeQuota) || freeQuota <= 0) throw new TypeError('A valid free storage quota is required.');

  const baseUrl = new URL(String(publicUrl || ''));
  if (baseUrl.protocol !== 'https:') throw new TypeError('The public Yuni Share URL must use HTTPS.');
  const actionUrl = new URL('/#membership', baseUrl).href;
  const policyUrl = new URL('/privacy#retention-and-deletion', baseUrl).href;
  const name = inlineText(displayName, 'there');
  const planName = PLAN_LABELS.get(String(planId).toLowerCase()) || inlineText(planId, 'Paid');
  const planLabel = `${planName} · ${formatStorage(planQuota)}`;
  const expiresLabel = formatUtcTime(expiry);
  const usedLabel = formatStorage(usage);
  const freeQuotaLabel = formatStorage(freeQuota);
  const retentionDeadlineLabel = formatUtcTime(expiry + PAID_STORAGE_RETENTION_MS);
  const overQuota = usage > freeQuota;

  const retentionText = overQuota
    ? `Your current usage is above the free ${freeQuotaLabel} quota. When the membership expires, a 15-calendar-day retention period will begin. You can still sign in, unlock, preview, download, and delete files during that period, but uploads that maintain or increase the overage will be restricted. If the account is still over quota at ${retentionDeadlineLabel}, Yuni Share will permanently delete the newest complete encrypted files first until usage is within the available quota. Restoring enough paid capacity or reducing usage to the quota before the deadline stops this cleanup.`
    : `Your current usage is within the free ${freeQuotaLabel} quota, so the 15-calendar-day over-quota cleanup will not apply if your usage remains within the available quota when the membership expires. If the account is over quota at expiration, the same retention period and newest-complete-file-first deletion rule will apply.`;

  const text = [
    `Hi ${name},`,
    `Your Yuni Share ${planName} membership will expire in 3 days, on ${expiresLabel}.`,
    `Plan: ${planLabel}\nCurrent usage: ${usedLabel}\nFree storage after expiration: ${freeQuotaLabel}`,
    'An active base membership cannot be repurchased or extended before it expires. After expiration, open Membership and select the plan you want to activate.',
    retentionText,
    'The 15-day paid-capacity retention rule is separate from the 30-day or 60-day account-deletion recovery period.',
    `Review the full Retention and Deletion policy: ${policyUrl}`,
    'We recommend keeping an independent backup of important files. If you have already taken the required action, you may disregard this notice.'
  ].join('\n\n');

  return {
    subject: 'Yuni Share · Your Membership Expires in 3 Days',
    text,
    actionUrl,
    actionLabel: 'Review Membership',
    template: MEMBERSHIP_EXPIRY_TEMPLATE,
    templateData: {
      displayName: name,
      planLabel,
      usedLabel,
      expiresLabel,
      freeQuotaLabel,
      retentionDeadlineLabel,
      overQuota,
      policyUrl
    }
  };
}

export function membershipExpiryIdempotencyKey(userId, expiresAt) {
  const digest = crypto.createHash('sha256')
    .update(`yuni-share-membership-expiry-v1:${userId}:${expiresAt}`)
    .digest('hex');
  return `yuni-share-expiry-${digest}`;
}

export function installMembershipExpiryReminderSchema(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS membership_expiry_reminders (
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      membership_expires_at INTEGER NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('pending', 'failed', 'sent')),
      attempts INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL,
      last_attempt_at INTEGER,
      sent_at INTEGER,
      last_error TEXT,
      PRIMARY KEY(user_id, membership_expires_at)
    );
    CREATE INDEX IF NOT EXISTS membership_expiry_reminders_pending
      ON membership_expiry_reminders(status, last_attempt_at);
  `);
}

export function createMembershipExpiryReminderService({
  db,
  sendMail,
  getUsage,
  publicUrl,
  freeQuotaBytes = DEFAULT_FREE_QUOTA_BYTES,
  retryMs = DEFAULT_RETRY_MS,
  batchSize = 25
}) {
  if (!db || typeof db.prepare !== 'function') throw new TypeError('A database is required.');
  if (typeof sendMail !== 'function') throw new TypeError('A mail sender is required.');
  if (typeof getUsage !== 'function') throw new TypeError('A usage reader is required.');
  installMembershipExpiryReminderSchema(db);

  const due = db.prepare(`SELECT
      u.id AS user_id, u.username, u.email,
      s.plan_id, s.quota_bytes, s.expires_at,
      r.sent_at, r.last_attempt_at
    FROM subscriptions s
    JOIN users u ON u.id = s.user_id
    LEFT JOIN membership_expiry_reminders r
      ON r.user_id = s.user_id AND r.membership_expires_at = s.expires_at
    WHERE u.email IS NOT NULL AND trim(u.email) != ''
      AND s.expires_at > ? AND s.expires_at <= ?
      AND r.sent_at IS NULL
      AND (r.last_attempt_at IS NULL OR r.last_attempt_at <= ?)
    ORDER BY s.expires_at ASC, u.id ASC
    LIMIT ?`);
  const createAttempt = db.prepare(`INSERT OR IGNORE INTO membership_expiry_reminders(
      user_id, membership_expires_at, status, attempts, created_at
    ) VALUES (?, ?, 'pending', 0, ?)`);
  const markAttempt = db.prepare(`UPDATE membership_expiry_reminders
    SET status = 'pending', attempts = attempts + 1, last_attempt_at = ?, last_error = NULL
    WHERE user_id = ? AND membership_expires_at = ? AND sent_at IS NULL`);
  const markSent = db.prepare(`UPDATE membership_expiry_reminders
    SET status = 'sent', sent_at = ?, last_error = NULL
    WHERE user_id = ? AND membership_expires_at = ?`);
  const markFailed = db.prepare(`UPDATE membership_expiry_reminders
    SET status = 'failed', last_error = ?
    WHERE user_id = ? AND membership_expires_at = ? AND sent_at IS NULL`);
  const inFlight = new Set();

  return {
    async deliverDue(now = Date.now()) {
      const summary = { due: 0, sent: 0, failed: 0, skipped: 0 };
      const rows = due.all(now, now + MEMBERSHIP_EXPIRY_REMINDER_MS, now - retryMs, batchSize);
      summary.due = rows.length;
      for (const row of rows) {
        const key = `${row.user_id}:${row.expires_at}`;
        if (inFlight.has(key)) {
          summary.skipped += 1;
          continue;
        }
        inFlight.add(key);
        try {
          createAttempt.run(row.user_id, row.expires_at, now);
          if (!markAttempt.run(now, row.user_id, row.expires_at).changes) {
            summary.skipped += 1;
            continue;
          }
          const message = membershipExpiryReminderMessage({
            displayName: row.username,
            planId: row.plan_id,
            planQuotaBytes: row.quota_bytes,
            expiresAt: row.expires_at,
            usedBytes: getUsage(row.user_id),
            freeQuotaBytes,
            publicUrl
          });
          const result = await sendMail({
            to: row.email,
            ...message,
            idempotencyKey: membershipExpiryIdempotencyKey(row.user_id, row.expires_at)
          });
          if (!result?.ok) throw new Error(result?.error || `Mail service returned ${result?.status || 'an error'}.`);
          markSent.run(now, row.user_id, row.expires_at);
          summary.sent += 1;
        } catch (error) {
          markFailed.run(String(error instanceof Error ? error.message : error).slice(0, 500), row.user_id, row.expires_at);
          summary.failed += 1;
        } finally {
          inFlight.delete(key);
        }
      }
      return summary;
    }
  };
}
