const $ = selector => document.querySelector(selector);
const unsafeMarkup = /<(?:script|iframe|object|embed|base|link|meta|style|img|audio|video|source|foreignobject|form|input|textarea|select|template|math|animate|set|use|image)\b|(?:^|\s)on[a-z0-9_-]+\s*=|(?:href|src|xlink:href)\s*=\s*["']?\s*(?:javascript:|data:)|\sstyle\s*=|\ssrcdoc\s*=/i;
const trustedHtmlPolicy = window.trustedTypes?.createPolicy('yuni-share', {
  createHTML(value) {
    const markup = String(value);
    if (unsafeMarkup.test(markup)) throw new TypeError('拒绝不安全的页面标记');
    return markup;
  }
});

function setTrustedHtml(node, value) {
  node.innerHTML = trustedHtmlPolicy ? trustedHtmlPolicy.createHTML(value) : String(value);
}

const authView = $('#authView');
const driveView = $('#driveView');
const sessionLoading = $('#sessionLoading');
const authForm = $('#authForm');
const uploads = new Map();
let selectedUploadIds = new Set();
const downloads = new Map();
const remoteRecoveryAttemptAt = new Map();
const FILE_UPLOAD_CONCURRENCY = 3;
const UPLOAD_WORKER_STAGGER_MS = 60;
const SERVER_CHUNK_SIZE = 16 * 1024 * 1024;
const GCM_TAG_BYTES = 16;
const LEGACY_PLAINTEXT_CHUNK_SIZE = SERVER_CHUNK_SIZE - GCM_TAG_BYTES;
const PLAINTEXT_CHUNK_SIZE = SERVER_CHUNK_SIZE;
const ENCRYPTION_VERSION = 1;
const FILE_FORMAT_VERSION = 2;
const FILE_COMPRESSION_VERSION = 1;
const FILE_COMPRESSION_ALGORITHM = 'gzip';
const VAULT_KDF_ITERATIONS = 600000;
const VAULT_IDLE_TIMEOUT_MS = 15 * 60 * 1000;
const PREVIEW_DOWNLOAD_CONCURRENCY = 6;
const PREVIEW_CHUNK_CACHE_LIMIT = 32 * 1024 * 1024;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function transferConcurrency() {
  const userAgent = navigator.userAgent || '';
  const mobile = Boolean(navigator.userAgentData?.mobile)
    || /Android|iPhone|iPad|iPod|Mobile/i.test(userAgent)
    || (navigator.maxTouchPoints > 1 && window.innerWidth <= 1024);
  return mobile ? 3 : 6;
}

let authMode = 'login';
let me = null;
let vaultKey = null;
let listedFiles = new Map();
let lockedListingCollapsed = false;
let currentDirectory = '';
let knownFolders = [];
let managedFileId = '';
let managedFolderPath = '';
let encryptedFolderRecordsByPath = new Map();
let selectedFileIds = new Set();
let selectedFolderPaths = new Set();
let previewFileId = '';
let previewEditorDirty = false;
let previewEditorInitialContent = '';
let previewObjectUrl = '';
let previewController = null;
let previewRendererCleanup = null;
let previewChunkCacheBytes = 0;
const previewChunkCache = new Map();
const previewChunkInflight = new Map();
let previewPrefetchController = null;
let remoteUploadTimer = null;
let pendingUploadFiles = null;
let pendingPasskeyRecommendation = false;
let accountDeletionPasskeyProof = '';
let vaultPasskeyManagementProof = '';
let vaultPasskeyManagementKey = null;
let vaultPasskeyRemovalProof = '';
let paymentPollTimer = null;
let vaultIdleTimer = null;
let pendingVaultUnlock = null;
const membershipMagicHash = '#membership';
const initialMembershipHash = location.hash.toLowerCase();
let pendingMembershipMagicLink = initialMembershipHash === membershipMagicHash
  || (initialMembershipHash === '' && new URLSearchParams(location.search).get('open') === 'subscription');

async function api(url, options = {}) {
  let response;
  try {
    response = await fetch(url, options);
  } catch (error) {
    error.retryable = true;
    throw error;
  }
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(data.error || '请求失败');
    error.status = response.status;
    error.retryable = [408, 425, 429].includes(response.status) || response.status >= 500;
    throw error;
  }
  return data;
}

function secureExternalUrl(value) {
  let parsed;
  try {
    parsed = new URL(String(value || ''));
  } catch {
    throw new Error('外部服务返回了无效地址');
  }
  if (parsed.protocol !== 'https:') throw new Error('外部服务地址必须使用 HTTPS');
  return parsed.href;
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return (bytes / 1024 ** i).toFixed(i ? 1 : 0) + ' ' + units[i];
}

function formatDate(timestamp) {
  return new Intl.DateTimeFormat('en-US', {
    timeZone: 'America/New_York',
    month: '2-digit',
    day: '2-digit',
    year: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    second: '2-digit',
    hour12: true,
    timeZoneName: 'short'
  }).format(new Date(timestamp));
}

function normalizeFolderPath(value) {
  const segments = String(value || '').replace(/\\/g, '/').split('/').map(segment =>
    segment.replace(/[\u0000-\u001f\u007f]/g, '').trim()
  ).filter(segment => segment && segment !== '.' && segment !== '..');
  return segments.map(segment => segment.slice(0, 240)).join('/').slice(0, 2000);
}

function joinFolderPath(...values) {
  return normalizeFolderPath(values.filter(Boolean).join('/'));
}

function parentFolderPath(value) {
  const parts = normalizeFolderPath(value).split('/').filter(Boolean);
  parts.pop();
  return parts.join('/');
}

function extractFileExtension(filename) {
  if (!filename || typeof filename !== 'string' || !filename.includes('.')) return '';
  const parts = filename.split('.');
  if (parts.length <= 1 || !parts[0]) return '';
  return '.' + parts.pop();
}

function fileNameIsValid(value) {
  const name = String(value || '').trim();
  return Boolean(name) && name.length <= 240 && !/[\\/\u0000-\u001f\u007f]/.test(name);
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;'
  })[character]);
}

function abortError() {
  return new DOMException('上传已取消', 'AbortError');
}

function isAbortError(error) {
  return error?.name === 'AbortError';
}

function wait(milliseconds, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(abortError());
    const timer = setTimeout(resolve, milliseconds);
    signal?.addEventListener('abort', () => {
      clearTimeout(timer);
      reject(abortError());
    }, { once: true });
  });
}

async function withRetry(operation, { attempts = 3, signal, onRetry } = {}) {
  let lastError;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (signal?.aborted) throw abortError();
    try {
      return await operation();
    } catch (error) {
      if (signal?.aborted || isAbortError(error)) throw abortError();
      lastError = error;
      if (attempt < attempts - 1) {
        onRetry?.(attempt + 1);
        await wait(700 * (attempt + 1), signal);
      }
    }
  }
  throw lastError;
}

async function retryWhileOnline(operation, { signal, onRetry } = {}) {
  let attempt = 0;
  while (true) {
    if (signal?.aborted) throw abortError();
    try {
      return await operation();
    } catch (error) {
      if (signal?.aborted || isAbortError(error)) throw abortError();
      if (error.retryable === false) throw error;
      attempt += 1;
      const delay = Math.min(15000, 1000 * 2 ** Math.min(attempt - 1, 4));
      onRetry?.(attempt, delay, error);
      await wait(delay, signal);
    }
  }
}

function showToast(message) {
  const toast = $('#toast');
  toast.textContent = message;
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 2600);
}

let confirmActionResolver = null;

function closeConfirmModal(confirmed = false) {
  const modal = $('#confirmModal');
  const resolve = confirmActionResolver;
  confirmActionResolver = null;
  modal.hidden = true;
  resolve?.(confirmed);
}

function confirmAction({ eyebrow = '确认操作', title, message, confirmLabel = '确认' }) {
  if (confirmActionResolver) closeConfirmModal(false);
  $('#confirmModalEyebrow').textContent = eyebrow;
  $('#confirmModalTitle').textContent = title;
  $('#confirmModalCopy').textContent = message;
  $('#confirmAccept').textContent = confirmLabel;
  $('#confirmModal').hidden = false;
  $('#confirmCancel').focus();
  return new Promise(resolve => {
    confirmActionResolver = resolve;
  });
}

function closeAccountDeletionModal() {
  $('#accountDeletionModal').hidden = true;
  $('#accountDeletionPassword').value = '';
  $('#accountDeletionAcknowledgement').checked = false;
  $('#accountDeletionError').textContent = '';
  accountDeletionPasskeyProof = '';
}

async function openSubscriptionModal() {
  $('#subscriptionError').textContent = '';
  setTrustedHtml($('#subscriptionPlans'), '');
  setTrustedHtml($('#storageAddonPlans'), '');
  setTrustedHtml($('#activeStorageAddons'), '');
  $('#activeStorageAddons').hidden = true;
  $('#subscriptionModal').hidden = false;
  try {
    const [plans, current] = await Promise.all([api('/api/plans'), api('/api/subscription')]);
    const active = current.subscription;
    const storageAddons = Array.isArray(current.storageAddons) ? current.storageAddons : [];
    const hasActiveMembership = active.plan_id !== 'free' && Number(active.expires_at) > Date.now();
    const currentPlan = plans.plans[active.plan_id];
    $('#subscriptionStatus').textContent = hasActiveMembership
      ? `当前 ${currentPlan?.name || active.plan_id.toUpperCase()} · 总空间 ${formatBytes(current.totalQuotaBytes)} · 会员至 ${new Date(active.expires_at).toLocaleDateString('zh-CN')}`
      : `当前为免费版，含 ${formatBytes(active.quota_bytes)} 空间。选择一个基础会员后，可按需购买独立扩容包。`;
    $('#subscriptionCycleField').hidden = hasActiveMembership;
    const renderBasePlans = () => {
      if (hasActiveMembership) {
        setTrustedHtml($('#subscriptionPlans'), `<article class="subscription-current-plan"><div><span>当前基础会员</span><strong>${escapeHtml(currentPlan?.name || active.plan_id.toUpperCase())}</strong></div><b>${formatBytes(active.quota_bytes)}</b><p>有效期内不重复购买基础套餐；需要更多空间时可在下方反复购买叠加包。</p></article>`);
        return;
      }
      const cycle = $('#subscriptionCycle').value;
      setTrustedHtml($('#subscriptionPlans'), Object.entries(plans.plans).map(([id, plan]) =>
        `<article class="subscription-plan-card"><header><span class="plan-name">${escapeHtml(plan.name)}</span><span class="plan-price">¥${formatPriceCents(plan[cycle])}<small>/${cycle === 'yearly' ? '年' : '月'}</small></span></header><strong class="plan-capacity">${formatBytes(plan.quota)}</strong><p class="plan-description">${cycle === 'yearly' ? '365 天加密空间 · 年付立省 ¥' + formatPriceCents(plan.monthly * 12 - plan.yearly) : '30 天加密空间 · 到期后重新选择'}</p><button class="primary plan-action" type="button" data-order-type="subscription" data-plan-id="${id}" data-product-name="${escapeHtml(plan.name)} · ${formatBytes(plan.quota)}" ${plans.paymentEnabled ? '' : 'disabled'}>选择套餐</button></article>`).join(''));
    };
    const renderStorageAddons = () => {
      if (storageAddons.length) {
        const totalAddonQuota = storageAddons.reduce((sum, addon) => sum + Number(addon.quota_bytes), 0);
        $('#activeStorageAddons').hidden = false;
        setTrustedHtml($('#activeStorageAddons'), `<div class="active-addon-summary"><span>当前叠加权益</span><strong>${storageAddons.length} 笔 · +${formatBytes(totalAddonQuota)}</strong></div><div class="active-addon-items">${storageAddons.map(addon => {
          const product = plans.storageAddons[addon.addon_id];
          return `<div><span>${escapeHtml(product?.name || '存储叠加包')}</span><strong>+${formatBytes(addon.quota_bytes)}</strong><small>至 ${new Date(addon.expires_at).toLocaleDateString('zh-CN')}</small></div>`;
        }).join('')}</div>`);
      }
      if (!hasActiveMembership) {
        setTrustedHtml($('#storageAddonPlans'), '<div class="subscription-locked"><strong>先开通基础会员</strong><span>叠加包仅在基础会员有效期间计入可用空间。</span></div>');
        return;
      }
      setTrustedHtml($('#storageAddonPlans'), Object.entries(plans.storageAddons).map(([id, addon]) =>
        `<article class="subscription-plan-card addon-card"><header><span class="plan-name">${escapeHtml(addon.name)}</span><span class="plan-price">¥${formatPriceCents(addon.monthly)}<small>/月</small></span></header><strong class="plan-capacity">+${formatBytes(addon.quota)}</strong><p class="plan-description">独立 30 天 · 可重复购买并累加</p><button class="secondary plan-action" type="button" data-order-type="addon" data-plan-id="${id}" data-product-name="${escapeHtml(addon.name)} · 30 天" ${plans.paymentEnabled ? '' : 'disabled'}>购买叠加包</button></article>`).join(''));
    };
    if (!plans.paymentEnabled) $('#subscriptionError').textContent = '支付服务尚未配置。';
    $('#subscriptionCycle').onchange = renderBasePlans;
    renderBasePlans();
    renderStorageAddons();
  } catch (error) { $('#subscriptionError').textContent = error.message; }
}

function openPendingMembershipMagicLink() {
  if (!pendingMembershipMagicLink || !me) return;
  pendingMembershipMagicLink = false;
  const url = new URL(location.href);
  if (url.hash.toLowerCase() === membershipMagicHash) url.hash = '';
  if (url.searchParams.get('open') === 'subscription') url.searchParams.delete('open');
  history.replaceState(null, '', `${url.pathname}${url.search}${url.hash}`);
  setTimeout(() => void openSubscriptionModal(), 0);
}

async function startSubscriptionCheckout(button) {
  const orderType = button.dataset.orderType || 'subscription';
  button.disabled = true;
  $('#subscriptionError').textContent = '';
  try {
    const result = await api('/api/payment-orders', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        orderType,
        planId: button.dataset.planId,
        billingCycle: orderType === 'addon' ? 'monthly' : $('#subscriptionCycle').value
      })
    });
    const isAddon = result.orderType === 'addon';
    const payUrl = secureExternalUrl(result.payUrl);
    $('#paymentTitle').textContent = isAddon ? '前往收银台购买扩容包' : '前往收银台完成订阅';
    $('#paymentProduct').textContent = button.dataset.productName || (isAddon ? '独立月度扩容包' : 'Yuni Share 会员');
    $('#paymentLink').href = payUrl;
    $('#paymentHint').textContent = '支付完成后请返回本页，系统会自动确认结果。';
    $('#paymentModal').hidden = false;
    window.open(payUrl, '_blank', 'noopener');
    clearInterval(paymentPollTimer);
    paymentPollTimer = setInterval(async () => {
      try {
        const order = await api(`/api/payment-orders/${encodeURIComponent(result.orderNo)}`);
        if (order.status === 'paid') {
          clearInterval(paymentPollTimer);
          paymentPollTimer = null;
          $('#paymentModal').hidden = true;
          $('#subscriptionModal').hidden = true;
          await loadSession({ key: vaultKey });
          showToast(isAddon ? '支付成功，额外存储已生效' : '支付成功，会员空间已开通');
        }
      } catch { /* the next poll retries */ }
    }, 2000);
  } catch (error) {
    $('#subscriptionError').textContent = error.message;
    button.disabled = false;
  }
}

function accountHasUsablePasskey() {
  return Boolean(webauthnSupported() && me?.encryption?.passkeys?.length);
}

function vaultHasUsablePasskey() {
  return accountHasUsablePasskey();
}

function resetAccountDeletionPasskeyVerification() {
  accountDeletionPasskeyProof = '';
  const section = $('#accountDeletionPasskeyVerification');
  section.hidden = false;
  section.classList.remove('is-verified');
  section.querySelector('strong').textContent = '推荐使用 Passkey';
  section.querySelector('span').textContent = '使用设备或密码管理器验证，无需输入账户登录密码。';
  $('#accountDeletionUsePasskey').textContent = '使用 Passkey 验证';
  $('#accountDeletionUsePasskey').disabled = false;
  $('#accountDeletionUsePassword').hidden = false;
}

function useAccountDeletionPassword() {
  accountDeletionPasskeyProof = '';
  $('#accountDeletionPasskeyVerification').hidden = true;
  $('#accountDeletionPasswordField').hidden = false;
  $('#accountDeletionPasswordSwitch').hidden = !accountHasUsablePasskey();
  $('#accountDeletionNoPasskeyHint').hidden = accountHasUsablePasskey();
  $('#accountDeletionPassword').required = true;
  setTimeout(() => $('#accountDeletionPassword').focus(), 0);
  showToast('已切换为登录密码验证');
}

function useAccountDeletionPasskey() {
  if (!accountHasUsablePasskey()) return;
  $('#accountDeletionPassword').value = '';
  $('#accountDeletionPasswordField').hidden = true;
  $('#accountDeletionPasswordSwitch').hidden = true;
  $('#accountDeletionNoPasskeyHint').hidden = true;
  $('#accountDeletionPassword').required = false;
  resetAccountDeletionPasskeyVerification();
  setTimeout(() => $('#accountDeletionUsePasskey').focus(), 0);
  showToast('已切换为 Passkey 验证');
}

function openAccountDeletionModal() {
  const canUsePasskey = accountHasUsablePasskey();
  $('#accountDeletionPassword').value = '';
  $('#accountDeletionAcknowledgement').checked = false;
  $('#accountDeletionError').textContent = '';
  accountDeletionPasskeyProof = '';
  $('#accountDeletionPasskeyVerification').hidden = !canUsePasskey;
  $('#accountDeletionPasswordField').hidden = canUsePasskey;
  $('#accountDeletionPasswordSwitch').hidden = true;
  $('#accountDeletionNoPasskeyHint').hidden = canUsePasskey;
  $('#accountDeletionPassword').required = !canUsePasskey;
  if (canUsePasskey) resetAccountDeletionPasskeyVerification();
  document.querySelector('input[name="accountDeletionDays"][value="30"]').checked = true;
  $('#accountDeletionModal').hidden = false;
  setTimeout(() => (canUsePasskey ? $('#accountDeletionUsePasskey') : $('#accountDeletionPassword')).focus(), 0);
}

function closeCancelDeletionModal() {
  $('#cancelDeletionModal').hidden = true;
  $('#cancelDeletionToken').value = '';
  $('#cancelDeletionError').textContent = '';
}

function openCancelDeletionModal(token) {
  $('#cancelDeletionToken').value = token;
  $('#cancelDeletionError').textContent = '';
  $('#cancelDeletionModal').hidden = false;
  setTimeout(() => $('#cancelDeletionSubmit').focus(), 0);
}

function closePasswordResetRequestModal() {
  $('#passwordResetRequestModal').hidden = true;
  $('#passwordResetRequestError').textContent = '';
}

function openPasswordResetRequestModal() {
  $('#passwordResetEmail').value = authForm.email.value || '';
  $('#passwordResetRequestError').textContent = '';
  $('#passwordResetRequestModal').hidden = false;
  setTimeout(() => $('#passwordResetEmail').focus(), 0);
}

function closePasswordResetModal() {
  $('#passwordResetModal').hidden = true;
  $('#passwordResetToken').value = '';
  $('#passwordResetPassword').value = '';
  $('#passwordResetConfirm').value = '';
  $('#passwordResetError').textContent = '';
}

function openPasswordResetModal(token) {
  $('#passwordResetToken').value = token;
  $('#passwordResetPassword').value = '';
  $('#passwordResetConfirm').value = '';
  $('#passwordResetError').textContent = '';
  $('#passwordResetModal').hidden = false;
  setTimeout(() => $('#passwordResetPassword').focus(), 0);
}

function openSecureActionFromLocation() {
  const params = new URLSearchParams(location.hash.slice(1));
  const cancellationToken = params.get('cancel-deletion') || '';
  const resetToken = params.get('reset-login-password') || '';
  if (!/^[A-Za-z0-9_-]{32,128}$/.test(cancellationToken) && !/^[A-Za-z0-9_-]{32,128}$/.test(resetToken)) return;
  history.replaceState(null, '', location.pathname + location.search);
  if (/^[A-Za-z0-9_-]{32,128}$/.test(cancellationToken)) openCancelDeletionModal(cancellationToken);
  else openPasswordResetModal(resetToken);
}

function bytesToBase64url(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64urlToBytes(value) {
  const padded = String(value).replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((String(value).length + 3) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}

function randomBytes(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function encryptionSupported() {
  return Boolean(window.crypto?.subtle && window.crypto?.getRandomValues);
}

function vaultAad() {
  return encoder.encode('yuni-share:vault-wrap:v1');
}

function vaultRecoveryAad() {
  return encoder.encode('yuni-share:vault-recovery-wrap:v1');
}

function vaultPasskeyAad(credentialId) {
  return encoder.encode('yuni-share:vault-passkey-wrap:v1:' + credentialId);
}

function metadataAad(uploadId) {
  return encoder.encode('yuni-share:file-metadata:v1:' + uploadId);
}

function folderMetadataAad(folderId) {
  return encoder.encode('yuni-share:folder-metadata:v1:' + folderId);
}

function chunkAad(uploadId, index) {
  return encoder.encode('yuni-share:file-chunk:v1:' + uploadId + ':' + index);
}

function chunkIv(nonce, index) {
  if (index > 0xffffffff) throw new Error('文件分片数量过多');
  const iv = new Uint8Array(12);
  iv.set(nonce, 0);
  new DataView(iv.buffer).setUint32(8, index, false);
  return iv;
}

async function derivePasswordWrappingKey(passphrase, salt, iterations) {
  const passwordBytes = encoder.encode(passphrase);
  let baseKey;
  try {
    baseKey = await crypto.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveKey']);
  } finally {
    passwordBytes.fill(0);
  }
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function importVaultKey(rawVaultKey) {
  return crypto.subtle.importKey('raw', rawVaultKey, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function wrapVaultKey(rawVaultKey, passphrase, additionalData = vaultAad()) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const wrappingKey = await derivePasswordWrappingKey(passphrase, salt, VAULT_KDF_ITERATIONS);
  const wrapped = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData },
    wrappingKey,
    rawVaultKey
  );
  return {
    version: ENCRYPTION_VERSION,
    iterations: VAULT_KDF_ITERATIONS,
    salt: bytesToBase64url(salt),
    iv: bytesToBase64url(iv),
    wrappedKey: bytesToBase64url(new Uint8Array(wrapped))
  };
}

async function unwrapVaultKey(passphrase, config, additionalData = vaultAad()) {
  if (!encryptionSupported()) throw new Error('此浏览器不支持 Web Crypto');
  if (!config || config.version !== ENCRYPTION_VERSION) throw new Error('加密空间配置不可用');
  const wrappingKey = await derivePasswordWrappingKey(
    passphrase,
    base64urlToBytes(config.salt),
    Number(config.iterations)
  );
  return new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64urlToBytes(config.iv), additionalData },
    wrappingKey,
    base64urlToBytes(config.wrappedKey)
  ));
}

async function unwrapVaultWithRecovery(recoveryPassword, recovery) {
  if (!recovery?.salt || !recovery?.iv || !recovery?.wrappedKey || !recovery?.iterations) {
    throw new Error('该账户尚未设置恢复密码');
  }
  return unwrapVaultKey(recoveryPassword, recovery, vaultRecoveryAad());
}

async function createVaultConfig(passphrase, recoveryPassword = '') {
  if (!encryptionSupported()) throw new Error('此浏览器不支持 Web Crypto，无法安全创建加密空间');
  const rawVaultKey = randomBytes(32);
  const [config, key, recovery] = await Promise.all([
    wrapVaultKey(rawVaultKey, passphrase),
    importVaultKey(rawVaultKey),
    recoveryPassword ? wrapVaultKey(rawVaultKey, recoveryPassword, vaultRecoveryAad()) : Promise.resolve(null)
  ]);
  rawVaultKey.fill(0);
  return { key, config, recovery };
}

async function unlockVault(passphrase, config) {
  const rawVaultKey = await unwrapVaultKey(passphrase, config);
  try {
    return await importVaultKey(rawVaultKey);
  } finally {
    rawVaultKey.fill(0);
  }
}

function webauthnSupported() {
  return Boolean(window.isSecureContext && window.PublicKeyCredential && navigator.credentials?.create && navigator.credentials?.get);
}

function bytesToArrayBuffer(bytes) {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

function webauthnExtensionsForBrowser(extensions = {}) {
  const result = { ...extensions };
  const first = extensions?.prf?.eval?.first;
  if (typeof first === 'string') {
    result.prf = { eval: { first: bytesToArrayBuffer(base64urlToBytes(first)) } };
  }
  return result;
}

function registrationOptionsForBrowser(options) {
  return {
    ...options,
    challenge: bytesToArrayBuffer(base64urlToBytes(options.challenge)),
    user: { ...options.user, id: bytesToArrayBuffer(base64urlToBytes(options.user.id)) },
    excludeCredentials: options.excludeCredentials?.map(credential => ({
      ...credential,
      id: bytesToArrayBuffer(base64urlToBytes(credential.id))
    })),
    extensions: webauthnExtensionsForBrowser(options.extensions)
  };
}

function authenticationOptionsForBrowser(options) {
  return {
    ...options,
    challenge: bytesToArrayBuffer(base64urlToBytes(options.challenge)),
    allowCredentials: options.allowCredentials?.map(credential => ({
      ...credential,
      id: bytesToArrayBuffer(base64urlToBytes(credential.id))
    })),
    extensions: webauthnExtensionsForBrowser(options.extensions)
  };
}

function credentialResponseForServer(credential) {
  const response = credential.response;
  const base = {
    id: credential.id,
    rawId: bytesToBase64url(new Uint8Array(credential.rawId)),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment || undefined,
    clientExtensionResults: {}
  };
  if (typeof response.getTransports === 'function') {
    return {
      ...base,
      response: {
        clientDataJSON: bytesToBase64url(new Uint8Array(response.clientDataJSON)),
        attestationObject: bytesToBase64url(new Uint8Array(response.attestationObject)),
        transports: response.getTransports()
      }
    };
  }
  return {
    ...base,
    response: {
      clientDataJSON: bytesToBase64url(new Uint8Array(response.clientDataJSON)),
      authenticatorData: bytesToBase64url(new Uint8Array(response.authenticatorData)),
      signature: bytesToBase64url(new Uint8Array(response.signature)),
      ...(response.userHandle ? { userHandle: bytesToBase64url(new Uint8Array(response.userHandle)) } : {})
    }
  };
}

function passkeyPrfOutput(credential) {
  const output = credential.getClientExtensionResults?.()?.prf?.results?.first;
  const bytes = output instanceof ArrayBuffer
    ? new Uint8Array(output)
    : ArrayBuffer.isView(output)
      ? new Uint8Array(output.buffer, output.byteOffset, output.byteLength)
      : null;
  if (!bytes || bytes.byteLength < 32) {
    throw new Error('所选 Passkey 不支持用于端到端加密的 PRF。请改用其他保存位置或加密密码。');
  }
  return new Uint8Array(bytes);
}

function passkeySetupError(error, stage) {
  if (stage === 'unlock-vault') {
    return new Error('加密密码不正确，无法为 Passkey 保护文件密钥。请输入注册时设置的“加密密码”，不是登录密码。');
  }
  if (error?.name === 'NotAllowedError') {
    const cancelled = new Error('Passkey 操作已取消或超时。请完成设备验证后重试。');
    cancelled.passkeyCancelled = true;
    return cancelled;
  }
  if (error?.name === 'NotSupportedError') {
    return new Error('当前选择的 Passkey 保存位置不支持端到端加密所需的 PRF。请更新浏览器或选择其他设备、密码管理器或安全密钥。');
  }
  if (error?.name === 'InvalidStateError') {
    return new Error('这个 Passkey 已存在或当前浏览器无法使用它。请在密码管理器中选择其他 Passkey 后重试。');
  }
  if (error?.message) return error;
  if (stage === 'create') {
    return new Error('浏览器未能创建 Passkey。请完成设备验证，或更换保存位置后重试。');
  }
  if (stage === 'activate') {
    return new Error('Passkey 已创建，但无法完成端到端加密激活。请确认所选 Passkey 支持 PRF，随后重试。');
  }
  return new Error('无法添加 Passkey。请重试；若问题持续，请更新浏览器后再试。');
}

function isPasskeyCancellation(error) {
  const message = String(error?.message || '');
  return Boolean(error?.passkeyCancelled)
    || error?.name === 'NotAllowedError'
    || /operation either timed out or was not allowed|passkey .*cancel|passkey .*cancell/i.test(message);
}

async function derivePasskeyWrappingKey(prfOutput, salt) {
  const baseKey = await crypto.subtle.importKey('raw', prfOutput, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: encoder.encode('yuni-share:vault-passkey-kdf:v1') },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function wrapVaultKeyWithPasskey(rawVaultKey, credentialId, prfOutput) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const wrappingKey = await derivePasskeyWrappingKey(prfOutput, salt);
  const wrapped = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: vaultPasskeyAad(credentialId) },
    wrappingKey,
    rawVaultKey
  );
  return {
    version: ENCRYPTION_VERSION,
    salt: bytesToBase64url(salt),
    iv: bytesToBase64url(iv),
    wrappedKey: bytesToBase64url(new Uint8Array(wrapped))
  };
}

async function unwrapVaultWithPasskey(prfOutput, passkey) {
  const config = passkey?.wrapping;
  if (!config?.salt || !config?.iv || !config?.wrappedKey) throw new Error('Passkey 配置不可用');
  const salt = base64urlToBytes(config.salt);
  const iv = base64urlToBytes(config.iv);
  const wrappingKey = await derivePasskeyWrappingKey(prfOutput, salt);
  return new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, additionalData: vaultPasskeyAad(passkey.credentialId) },
    wrappingKey,
    base64urlToBytes(config.wrappedKey)
  ));
}

async function unlockVaultWithPasskey(prfOutput, passkey) {
  const rawVaultKey = await unwrapVaultWithPasskey(prfOutput, passkey);
  try {
    return await importVaultKey(rawVaultKey);
  } finally {
    rawVaultKey.fill(0);
  }
}

async function encryptMetadata(uploadId, metadata) {
  const iv = randomBytes(12);
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: metadataAad(uploadId) },
    vaultKey,
    encoder.encode(JSON.stringify(metadata))
  );
  return { metadata: bytesToBase64url(new Uint8Array(encrypted)), metadataIv: bytesToBase64url(iv) };
}

async function decryptMetadata(file) {
  if (!vaultKey) throw new Error('加密空间已锁定');
  const plaintext = new Uint8Array(await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: base64urlToBytes(file.encrypted_metadata_iv),
      additionalData: metadataAad(file.upload_id || file.id)
    },
    vaultKey,
    base64urlToBytes(file.encrypted_metadata)
  ));
  let metadata;
  try {
    metadata = JSON.parse(decoder.decode(plaintext));
  } finally {
    plaintext.fill(0);
  }
  const legacyFormat = metadata?.version === ENCRYPTION_VERSION;
  const compressedFormat = metadata?.version === FILE_FORMAT_VERSION
    && metadata.compression?.version === FILE_COMPRESSION_VERSION
    && metadata.compression?.algorithm === FILE_COMPRESSION_ALGORITHM
    && metadata.compression?.framing === 'per-chunk';
  if ((!legacyFormat && !compressedFormat) || typeof metadata.name !== 'string'
    || !Number.isSafeInteger(metadata.size) || metadata.size < 0
    || !Number.isSafeInteger(metadata.plainChunkSize) || metadata.plainChunkSize < 1
    || typeof metadata.fileKey !== 'string' || typeof metadata.fileNonce !== 'string') {
    throw new Error('加密文件元数据无效');
  }
  return metadata;
}

async function encryptFolderMetadata(folderId, folderPath) {
  if (!vaultKey) throw new Error('加密空间已锁定');
  const iv = randomBytes(12);
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: folderMetadataAad(folderId) },
    vaultKey,
    encoder.encode(JSON.stringify({ version: ENCRYPTION_VERSION, kind: 'folder', path: normalizeFolderPath(folderPath) }))
  );
  return { metadata: bytesToBase64url(new Uint8Array(encrypted)), metadataIv: bytesToBase64url(iv) };
}

async function decryptFolderMetadata(folder) {
  if (!vaultKey) throw new Error('加密空间已锁定');
  const plaintext = new Uint8Array(await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: base64urlToBytes(folder.encrypted_metadata_iv),
      additionalData: folderMetadataAad(folder.id)
    },
    vaultKey,
    base64urlToBytes(folder.encrypted_metadata)
  ));
  let metadata;
  try {
    metadata = JSON.parse(decoder.decode(plaintext));
  } finally {
    plaintext.fill(0);
  }
  const folderPath = normalizeFolderPath(metadata?.path);
  if (metadata?.version !== ENCRYPTION_VERSION || metadata?.kind !== 'folder' || !folderPath) {
    throw new Error('加密文件夹元数据无效');
  }
  return { id: folder.id, path: folderPath };
}

function setMode(mode) {
  if (!['login','register'].includes(mode)) mode = 'login';
  authMode = mode;
  $('#loginTab').classList.toggle('active', mode === 'login');
  $('#registerTab').classList.toggle('active', mode === 'register');
  $('#authSubmit').textContent = mode === 'login' ? '登录' : mode === 'register' ? '创建加密账户' : '绑定邮箱并登录';
  $('#authSubmit').classList.toggle('primary', mode !== 'login');
  $('#authSubmit').classList.toggle('secondary', mode === 'login');
  $('#passwordLoginDivider').hidden = mode !== 'login';
  $('#usernameField').hidden = mode === 'login';
  $('#vaultPasswordField').hidden = mode !== 'register';
  $('#inviteField').hidden = true;
  $('#codeField').hidden = mode === 'login';
  $('#forgotPassword').hidden = mode !== 'login';
  $('#passkeyLogin').hidden = mode !== 'login';
  $('#passkeyLogin').disabled = mode === 'login' && !webauthnSupported();
  authForm.username.required = mode !== 'login';
  authForm.inviteCode.required = false;
  authForm.vaultPassword.required = mode === 'register';
  authForm.code.required = mode !== 'login';
  authForm.email.required = true;
  authForm.password.autocomplete = mode === 'register' ? 'new-password' : 'current-password';
  authForm.email.autocomplete = mode === 'login' ? 'username' : 'email';
  $('#authError').textContent = '';
}

function startCodeCountdown(seconds) {
  const button = $('#sendCode');
  let remaining = Number(seconds) || 60;
  button.disabled = true;
  button.textContent = remaining + ' 秒';
  const timer = setInterval(() => {
    remaining -= 1;
    button.textContent = remaining > 0 ? remaining + ' 秒' : '发送验证码';
    if (remaining <= 0) {
      clearInterval(timer);
      button.disabled = false;
    }
  }, 1000);
}

function vaultSecondaryActions(actions) {
  return '<div class="vault-desktop-settings">' + actions + '</div>'
    + '<details class="vault-mobile-settings"><summary>更多安全设置</summary><div class="vault-mobile-settings-menu">' + actions + '</div></details>';
}

function renderVaultStatus() {
  refreshVaultIdleTimer();
  const status = $('#vaultStatus');
  if (!me?.encryption) {
    setTrustedHtml(status, '<div><strong>端到端加密尚未设置</strong><span>旧账户必须先设置加密空间，才能上传新文件。现有测试文件已被清除。</span></div><button type="button" class="secondary vault-action" data-vault-action="setup">设置加密空间</button>');
    return;
  }
  const passkeyCount = me.encryption.passkeys?.length || 0;
  const hasPasskey = passkeyCount > 0 && webauthnSupported();
  const noPasskeyHint = '<span class="vault-passkey-hint">尚未添加 Passkey。解锁后可在“管理 Passkey”中添加，之后可用设备或密码管理器确认敏感操作。</span>';
  if (!vaultKey) {
    const recoveryAction = !passkeyCount && me.encryption.recovery
      ? '<button type="button" class="text-button vault-action" data-vault-action="recover">忘记加密密码？</button>'
      : '';
    const manageAction = '<button type="button" class="vault-quiet-action vault-action" data-vault-action="passkeys">管理 Passkey</button>';
    const unlockControls = hasPasskey
      ? '<div class="vault-auth-method"><button type="button" class="primary vault-action" data-vault-action="unlock-passkey">使用 Passkey 解锁</button><button type="button" class="secondary vault-inline-action vault-action" data-vault-action="unlock">使用加密密码解锁</button></div>'
      : '<div class="vault-auth-method"><button type="button" class="primary vault-action" data-vault-action="unlock">使用加密密码解锁</button>' + noPasskeyHint + '</div>';
    const resetAction = hasPasskey
      ? '<button type="button" class="vault-quiet-action vault-action vault-sensitive-action" data-vault-action="reset-with-passkey">重设加密密码</button>'
      : '';
    setTrustedHtml(status, '<div class="vault-status-copy"><p class="vault-status-label">端到端加密空间</p><strong>加密空间已锁定</strong><span>刷新、关闭页面或手动锁定后，需要使用加密密码或已验证的 Passkey 才能解锁。服务器无法读取文件内容。</span></div><div class="vault-status-overview"><span class="vault-state-chip is-locked">已锁定</span><span class="vault-passkey-summary">' + (passkeyCount ? 'Passkey 已启用' : '仅加密密码') + '</span></div><div class="vault-status-actions"><div class="vault-action-group">' + unlockControls + '</div><div class="vault-status-notes">' + vaultSecondaryActions(manageAction + resetAction + recoveryAction) + '</div></div>');
    return;
  }
  const recoveryAction = !passkeyCount && me.encryption.recovery
    ? '<span class="vault-recovery-note">恢复密码已设置</span>'
    : '';
  const manageAction = '<button type="button" class="vault-quiet-action vault-action" data-vault-action="passkeys">管理 Passkey</button>';
  const changeControls = hasPasskey
    ? '<div class="vault-auth-method"><button type="button" class="primary vault-action" data-vault-action="reset-with-passkey">使用 Passkey 修改加密密码</button><button type="button" class="secondary vault-inline-action vault-action" data-vault-action="change">使用加密密码修改</button></div>'
    : '<div class="vault-auth-method"><button type="button" class="primary vault-action" data-vault-action="change">修改加密密码</button>' + noPasskeyHint + '</div>';
  const unlockedSecondaryActions = manageAction + recoveryAction + '<button type="button" class="secondary vault-action vault-lock-action" data-vault-action="lock">锁定空间</button>';
  setTrustedHtml(status, '<div class="vault-status-copy"><p class="vault-status-label">端到端加密空间</p><strong>加密空间已解锁</strong><span>文件仅在当前浏览器中解密。刷新、关闭页面或空闲 15 分钟后，空间会自动锁定。</span></div><div class="vault-status-overview"><span class="vault-state-chip is-unlocked">E2EE 已解锁</span><span class="vault-passkey-summary">' + (passkeyCount ? 'Passkey 已启用' : '未添加 Passkey') + '</span></div><div class="vault-status-actions"><div class="vault-action-group">' + changeControls + '</div><div class="vault-status-notes">' + vaultSecondaryActions(unlockedSecondaryActions) + '</div></div>');
}

function refreshVaultIdleTimer() {
  clearTimeout(vaultIdleTimer);
  vaultIdleTimer = null;
  if (!vaultKey) return;
  vaultIdleTimer = setTimeout(() => {
    if (uploads.size || downloads.size) {
      refreshVaultIdleTimer();
      return;
    }
    lockVault('加密空间因空闲 15 分钟已自动锁定');
  }, VAULT_IDLE_TIMEOUT_MS);
}

function lockVault(message = '加密空间已锁定，进行中的传输已取消') {
  clearExplorerPrivateState();
  if (!vaultKey) return;
  clearTimeout(vaultIdleTimer);
  vaultIdleTimer = null;
  vaultKey = null;
  for (const item of listedFiles.values()) {
    item.name = '';
    item.path = '';
    item.type = '';
  }
  listedFiles = new Map();
  knownFolders = [];
  encryptedFolderRecordsByPath = new Map();
  currentDirectory = '';
  selectedFileIds = new Set();
  setTrustedHtml($('#fileList'), '');
  clearVaultPasskeyManagementMaterial();
  vaultPasskeyRemovalProof = '';
  accountDeletionPasskeyProof = '';
  closeFileManageModal();
  closePreviewModal();
  clearPreviewChunkCache();
  for (const task of uploads.values()) void cancelUpload(task);
  for (const task of downloads.values()) void cancelDownload(task);
  renderVaultStatus();
  loadFiles().catch(() => {});
  refreshRemoteUploads().catch(() => {});
  showToast(message);
}

async function loadSiteAnnouncement() {
  const node = $('#siteAnnouncement');
  if (!node) return;
  try {
    const announcement = await api('/api/site/announcement');
    if (!announcement.enabled) {
      node.hidden = true;
      return;
    }
    setTrustedHtml(node, '<div class="site-announcement-copy"><p class="eyebrow">YUNI SHARE · 公告</p><h2>'
      + escapeHtml(announcement.title) + '</h2><p>' + escapeHtml(announcement.intro || '') + '</p><div class="site-announcement-body">'
      + announcement.bodyHtml + '</div><small>' + escapeHtml(announcement.meta || '') + '</small></div>');
    node.hidden = false;
  } catch {
    node.hidden = true;
  }
}

function openVaultModal(mode) {
  const modal = $('#vaultModal');
  modal.dataset.mode = mode;
  const setup = mode === 'setup';
  const change = mode === 'change';
  const recover = mode === 'recover';
  const setRecovery = mode === 'set-recovery';
  const resetRecovery = mode === 'reset-recovery';
  const resetWithPasskey = mode === 'reset-with-passkey';
  const canUsePasskey = mode === 'unlock' && vaultHasUsablePasskey();
  $('#vaultModalTitle').textContent = setup ? '设置端到端加密空间'
    : change ? '修改加密密码'
      : recover ? '恢复加密空间'
        : setRecovery ? '设置恢复密码'
          : resetRecovery ? '重设恢复密码'
            : resetWithPasskey ? '使用 Passkey 修改加密密码'
              : '解锁加密空间';
  $('#vaultModalCopy').textContent = setup
    ? '请设置独立的加密密码。之后建议添加 Passkey，用于登录、解锁和重设加密密码。'
    : change
      ? '验证当前加密密码和登录密码后，会用新密码重新包裹同一把数据密钥。文件不会被解密、上传或改动。'
      : recover
        ? '输入恢复密码、新的加密密码和登录密码。恢复密码只在当前浏览器中用于恢复加密空间。'
        : setRecovery
          ? '设置恢复密码后，浏览器会自动生成恢复所需的加密材料并交由服务器保存；服务器无法直接解密文件。'
          : resetRecovery
            ? '旧恢复密码无法显示或找回。继续后会要求你验证 Passkey，并在当前浏览器中为同一把数据密钥设置新的恢复密码。'
            : resetWithPasskey
              ? '这是推荐方式。验证 Passkey 后，浏览器会用新加密密码重新包裹同一把数据密钥。文件不会被解密、上传或改动。'
              : (canUsePasskey ? '优先使用 Passkey 解锁；也可改用加密密码。加密密码只在当前浏览器中使用。' : '加密密码只在当前浏览器中用于解锁本地加密密钥，不会发送或保存到服务器。解锁后建议添加 Passkey。');
  $('#vaultUnlockPasskey').hidden = !canUsePasskey;
  $('#vaultSubmit').textContent = setup ? '创建加密空间'
    : change ? '更新加密密码'
      : recover ? '恢复并设置新密码'
        : setRecovery ? '保存恢复密码'
          : resetRecovery ? '验证 Passkey 并保存新恢复密码'
            : resetWithPasskey ? '使用 Passkey 验证并更新密码'
              : '解锁';
  $('#vaultAccountPasswordField').hidden = !(setup || change || recover || setRecovery);
  $('#vaultNewPasswordField').hidden = !(change || recover || resetWithPasskey);
  $('#vaultPasswordConfirmModalField').hidden = !(setup || change || recover || resetWithPasskey);
  $('#vaultRecoveryPasswordField').hidden = !(setup || recover || setRecovery || resetRecovery);
  $('#vaultRecoveryPasswordConfirmField').hidden = !(setup || setRecovery || resetRecovery);
  $('#vaultPasswordFieldModal').hidden = recover || resetRecovery || resetWithPasskey;
  $('#vaultPasswordFieldModal').firstChild.textContent = setup ? '加密密码'
    : change || setRecovery ? '当前加密密码'
      : '加密密码';
  $('#vaultAccountPassword').required = setup || change || recover || setRecovery;
  $('#vaultPassword').required = !(recover || resetRecovery || resetWithPasskey);
  $('#vaultNewPassword').required = change || recover || resetWithPasskey;
  $('#vaultPasswordConfirmModal').required = setup || change || recover || resetWithPasskey;
  $('#vaultRecoveryPassword').required = setup || recover || setRecovery || resetRecovery;
  $('#vaultRecoveryPasswordConfirm').required = setup || setRecovery || resetRecovery;
  $('#vaultPassword').autocomplete = setup ? 'new-password' : 'current-password';
  $('#vaultError').textContent = '';
  $('#vaultPassword').value = '';
  $('#vaultNewPassword').value = '';
  $('#vaultAccountPassword').value = '';
  $('#vaultPasswordConfirmModal').value = '';
  $('#vaultRecoveryPassword').value = '';
  $('#vaultRecoveryPasswordConfirm').value = '';
  modal.hidden = false;
  setTimeout(() => (
    (recover || resetRecovery) ? $('#vaultRecoveryPassword')
      : resetWithPasskey ? $('#vaultNewPassword')
        : $('#vaultPassword')
  ).focus(), 0);
}

function waitForVaultUnlock() {
  if (vaultKey) return Promise.resolve();
  if (!pendingVaultUnlock) {
    let resolve;
    let reject;
    const promise = new Promise((onResolve, onReject) => {
      resolve = onResolve;
      reject = onReject;
    });
    pendingVaultUnlock = { promise, resolve, reject };
  }
  openVaultModal(me?.encryption?.wrappedKey ? 'unlock' : 'setup');
  return pendingVaultUnlock.promise;
}

function resolvePendingVaultUnlock() {
  const pending = pendingVaultUnlock;
  pendingVaultUnlock = null;
  pending?.resolve();
}

function cancelPendingVaultUnlock() {
  const pending = pendingVaultUnlock;
  pendingVaultUnlock = null;
  pending?.reject(new DOMException('已取消解锁', 'AbortError'));
}

function closeVaultModal() {
  if (!vaultKey) cancelPendingVaultUnlock();
  $('#vaultModal').hidden = true;
  $('#vaultPassword').value = '';
  $('#vaultNewPassword').value = '';
  $('#vaultAccountPassword').value = '';
  $('#vaultPasswordConfirmModal').value = '';
  $('#vaultRecoveryPassword').value = '';
  $('#vaultRecoveryPasswordConfirm').value = '';
  $('#vaultError').textContent = '';
}

function vaultPasskeyDescription(passkey) {
  const device = passkey.deviceType === 'multiDevice'
    ? '可同步 Passkey'
    : passkey.deviceType === 'singleDevice'
      ? '设备绑定 Passkey'
      : 'Passkey';
  const backup = passkey.deviceType === 'multiDevice'
    ? (passkey.backedUp ? ' · 已备份到密码管理器' : ' · 等待密码管理器备份')
    : '';
  const used = passkey.lastUsedAt ? ' · 最近使用 ' + formatDate(passkey.lastUsedAt) : '';
  return device + backup + used;
}

function renderVaultPasskeyList() {
  const list = $('#vaultPasskeyList');
  const passkeys = me?.encryption?.passkeys || [];
  if (!passkeys.length) {
    setTrustedHtml(list, '<div class="passkey-empty">尚未添加 Passkey。请妥善保存加密密码，否则无法恢复加密文件。</div>');
    return;
  }
  setTrustedHtml(list, passkeys.map((passkey, index) => '<div class="passkey-row passkey-row-active"><div><span class="passkey-state">已启用</span><strong>Passkey ' + (index + 1)
    + '</strong><span>' + escapeHtml(vaultPasskeyDescription(passkey)) + '</span></div><button class="secondary remove-vault-passkey" type="button" data-credential-id="'
    + passkey.credentialId + '">移除</button></div>').join('')
    + '<p class="passkey-list-note">此账户已使用 Passkey 保护。若要在另一台设备上使用，请在你的浏览器或密码管理器中同步该 Passkey。</p>');
}

function closeVaultPasskeyModal() {
  clearVaultPasskeyManagementMaterial();
  vaultPasskeyRemovalProof = '';
  $('#vaultPasskeyModal').hidden = true;
  $('#vaultPasskeyForm').reset();
  $('#vaultPasskeyRemoveForm').reset();
  $('#vaultPasskeyRemoveForm').hidden = true;
  $('#vaultPasskeyForm').hidden = Boolean(me?.encryption?.passkeys?.length);
  $('#vaultPasskeyError').textContent = '';
  $('#vaultPasskeyRemoveError').textContent = '';
}

function clearVaultPasskeyManagementMaterial() {
  vaultPasskeyManagementKey?.fill(0);
  vaultPasskeyManagementKey = null;
  vaultPasskeyManagementProof = '';
}

function resetVaultPasskeyVerification() {
  clearVaultPasskeyManagementMaterial();
  const canUsePasskey = vaultHasUsablePasskey();
  $('#vaultPasskeyVerification').hidden = !canUsePasskey;
  $('#vaultPasskeyVerification').classList.remove('is-verified');
  $('#vaultPasskeyVerification').querySelector('strong').textContent = '推荐使用 Passkey';
  $('#vaultPasskeyVerification').querySelector('span').textContent = '使用现有 Passkey 验证并保护新的 Passkey，无需输入两个密码。';
  $('#vaultPasskeyUsePasskey').textContent = '使用 Passkey 验证';
  $('#vaultPasskeyUsePasskey').disabled = false;
  $('#vaultPasskeyUsePassword').hidden = false;
  $('#vaultPasskeyAccountPassword').value = '';
  $('#vaultPasskeyEncryptionPassword').value = '';
  $('#vaultPasskeyAccountPasswordField').hidden = canUsePasskey;
  $('#vaultPasskeyEncryptionPasswordField').hidden = canUsePasskey;
  $('#vaultPasskeyAccountPassword').required = !canUsePasskey;
  $('#vaultPasskeyEncryptionPassword').required = !canUsePasskey;
  $('#vaultPasskeyPasswordSwitch').hidden = true;
  $('#vaultPasskeyNoPasskeyHint').hidden = canUsePasskey;
}

function useVaultPasskeyPassword() {
  clearVaultPasskeyManagementMaterial();
  $('#vaultPasskeyVerification').hidden = true;
  $('#vaultPasskeyAccountPasswordField').hidden = false;
  $('#vaultPasskeyEncryptionPasswordField').hidden = false;
  $('#vaultPasskeyAccountPassword').required = true;
  $('#vaultPasskeyEncryptionPassword').required = true;
  $('#vaultPasskeyPasswordSwitch').hidden = !vaultHasUsablePasskey();
  $('#vaultPasskeyNoPasskeyHint').hidden = vaultHasUsablePasskey();
  setTimeout(() => $('#vaultPasskeyAccountPassword').focus(), 0);
}

function useVaultPasskeyPasskey() {
  if (!vaultHasUsablePasskey()) return;
  resetVaultPasskeyVerification();
  setTimeout(() => $('#vaultPasskeyUsePasskey').focus(), 0);
}

function resetVaultPasskeyRemovalVerification() {
  vaultPasskeyRemovalProof = '';
  const canUsePasskey = vaultHasUsablePasskey();
  $('#vaultPasskeyRemoveVerification').hidden = !canUsePasskey;
  $('#vaultPasskeyRemoveVerification').classList.remove('is-verified');
  $('#vaultPasskeyRemoveVerification').querySelector('strong').textContent = '推荐使用 Passkey';
  $('#vaultPasskeyRemoveVerification').querySelector('span').textContent = '使用设备或密码管理器确认此操作，无需输入账户登录密码。';
  $('#vaultPasskeyRemoveUsePasskey').textContent = '使用 Passkey 验证';
  $('#vaultPasskeyRemoveUsePasskey').disabled = false;
  $('#vaultPasskeyRemoveUsePassword').hidden = false;
  $('#vaultPasskeyRemovePassword').value = '';
  $('#vaultPasskeyRemovePasswordField').hidden = canUsePasskey;
  $('#vaultPasskeyRemovePassword').required = !canUsePasskey;
  $('#vaultPasskeyRemovePasswordSwitch').hidden = true;
}

function useVaultPasskeyRemovalPassword() {
  vaultPasskeyRemovalProof = '';
  $('#vaultPasskeyRemoveVerification').hidden = true;
  $('#vaultPasskeyRemovePasswordField').hidden = false;
  $('#vaultPasskeyRemovePassword').required = true;
  $('#vaultPasskeyRemovePasswordSwitch').hidden = !vaultHasUsablePasskey();
  setTimeout(() => $('#vaultPasskeyRemovePassword').focus(), 0);
}

function useVaultPasskeyRemovalPasskey() {
  if (!vaultHasUsablePasskey()) return;
  resetVaultPasskeyRemovalVerification();
  setTimeout(() => $('#vaultPasskeyRemoveUsePasskey').focus(), 0);
}

function openVaultPasskeyModal() {
  if (!me?.encryption) {
    showToast('请先设置端到端加密空间');
    return;
  }
  $('#vaultPasskeyForm').reset();
  $('#vaultPasskeyPreference').value = 'any';
  $('#vaultPasskeyRemoveForm').reset();
  $('#vaultPasskeyRemoveForm').hidden = true;
  const hasPasskey = Boolean(me.encryption.passkeys?.length);
  $('#vaultPasskeyForm').hidden = hasPasskey;
  $('#vaultPasskeyCopy').textContent = hasPasskey
    ? '你的 Passkey 已启用并由浏览器、设备或密码管理器保存。要在另一台设备上使用，请同步同一个 Passkey；YUNI Share 无法读取其私钥。'
    : 'Passkey 的私钥由你的浏览器、设备或密码管理器保存。YUNI Share 不会知道它的保存位置，也无法读取它。';
  if (!hasPasskey) resetVaultPasskeyVerification();
  $('#vaultPasskeyError').textContent = webauthnSupported() ? '' : '当前浏览器不支持 WebAuthn Passkey；请使用受支持的现代浏览器。';
  $('#vaultPasskeyRemoveError').textContent = '';
  $('#vaultPasskeySubmit').disabled = hasPasskey || !webauthnSupported();
  renderVaultPasskeyList();
  $('#vaultPasskeyModal').hidden = false;
  setTimeout(() => (hasPasskey ? $('.remove-vault-passkey') : $('#vaultPasskeyAccountPassword')).focus(), 0);
}

function openVaultPasskeyRecommendation() {
  if (!webauthnSupported()) return;
  pendingPasskeyRecommendation = true;
  $('#vaultPasskeyRecommendationError').textContent = '';
  $('#vaultPasskeyRecommendationModal').hidden = false;
}

function closeVaultPasskeyRecommendation() {
  pendingPasskeyRecommendation = false;
  $('#vaultPasskeyRecommendationError').textContent = '';
  $('#vaultPasskeyRecommendationModal').hidden = true;
}

function openVaultPasskeyRemoval(credentialId) {
  const passkey = me?.encryption?.passkeys?.find(item => item.credentialId === credentialId);
  if (!passkey) return;
  $('#vaultPasskeyForm').hidden = true;
  $('#vaultPasskeyRemoveId').value = credentialId;
  const isLastPasskey = (me?.encryption?.passkeys?.length || 0) === 1;
  $('#vaultPasskeyRemoveCopy').textContent = (isLastPasskey
    ? '这是唯一的 Passkey。移除后将不能再用 Passkey 登录、解锁或重设加密密码；请确认你仍记得加密密码。'
    : '移除后，该 Passkey 将不能再解锁此加密空间。') + vaultPasskeyDescription(passkey);
  $('#vaultPasskeyRemoveError').textContent = '';
  $('#vaultPasskeyRemoveForm').hidden = false;
  resetVaultPasskeyRemovalVerification();
  setTimeout(() => (vaultHasUsablePasskey() ? $('#vaultPasskeyRemoveUsePasskey') : $('#vaultPasskeyRemovePassword')).focus(), 0);
}

function cancelVaultPasskeyRemoval() {
  vaultPasskeyRemovalProof = '';
  $('#vaultPasskeyRemoveForm').reset();
  $('#vaultPasskeyRemoveForm').hidden = true;
  $('#vaultPasskeyForm').hidden = Boolean(me?.encryption?.passkeys?.length);
  $('#vaultPasskeyRemoveError').textContent = '';
}

async function addVaultPasskey({ accountPassword = '', encryptionPassword = '', passkeyProof = '', rawVaultKey = null, preference = 'any' }) {
  if (!webauthnSupported()) throw new Error('当前浏览器不支持 Passkey');
  if (!passkeyProof && accountPassword.length < 10) throw new Error('请使用 Passkey 验证，或输入登录密码');
  if (!rawVaultKey && encryptionPassword.length < 12) throw new Error('请使用 Passkey 验证，或输入加密密码');
  let keyMaterial = rawVaultKey;
  let pendingCredentialId = '';
  let activated = false;
  let stage = 'unlock-vault';
  try {
    if (!keyMaterial) {
      try {
        keyMaterial = await unwrapVaultKey(encryptionPassword, me.encryption);
      } catch (error) {
        throw passkeySetupError(error, 'unlock-vault');
      }
    }
    stage = 'verify-account';
    const registrationStart = await api('/api/vault-passkeys/registration/options', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: accountPassword, passkeyProof, preference })
    });
    stage = 'create';
    let created;
    try {
      created = await navigator.credentials.create({
        publicKey: registrationOptionsForBrowser(registrationStart.options)
      });
    } catch (error) {
      throw passkeySetupError(error, 'create');
    }
    if (!created) throw new Error('未创建 Passkey');
    stage = 'verify-registration';
    const registration = await api('/api/vault-passkeys/registration/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        challengeId: registrationStart.challengeId,
        response: credentialResponseForServer(created)
      })
    });
    pendingCredentialId = registration.credentialId;
    stage = 'activate';
    let assertion;
    try {
      assertion = await navigator.credentials.get({
        publicKey: authenticationOptionsForBrowser(registration.activation.options)
      });
    } catch (error) {
      throw passkeySetupError(error, 'activate');
    }
    if (!assertion) throw new Error('Passkey 激活已取消');
    if (assertion.id !== pendingCredentialId) throw new Error('Passkey 与激活请求不匹配');
    let prfOutput;
    try {
      prfOutput = passkeyPrfOutput(assertion);
    } catch (error) {
      throw passkeySetupError(error, 'activate');
    }
    let wrapping;
    try {
      wrapping = await wrapVaultKeyWithPasskey(keyMaterial, pendingCredentialId, prfOutput);
    } finally {
      prfOutput.fill(0);
    }
    await api('/api/vault-passkeys/' + encodeURIComponent(pendingCredentialId) + '/activate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        challengeId: registration.activation.challengeId,
        response: credentialResponseForServer(assertion),
        wrapping
      })
    });
    activated = true;
    me = await api('/api/me');
    renderVaultStatus();
  } catch (error) {
    if (pendingCredentialId && !activated && accountPassword) {
      await api('/api/vault-passkeys/' + encodeURIComponent(pendingCredentialId), {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: accountPassword })
      }).catch(() => {});
    }
    throw passkeySetupError(error, stage);
  } finally {
    keyMaterial?.fill(0);
  }
}

async function unlockWithVaultPasskey() {
  if (!webauthnSupported()) throw new Error('当前浏览器不支持 Passkey');
  const started = await api('/api/vault-passkeys/unlock/options', { method: 'POST' });
  const credential = await navigator.credentials.get({ publicKey: authenticationOptionsForBrowser(started.options) });
  if (!credential) throw new Error('未选择 Passkey');
  const credentialId = credential.id;
  const passkey = me?.encryption?.passkeys?.find(item => item.credentialId === credentialId);
  if (!passkey) throw new Error('所选 Passkey 不属于当前账户');
  const prfOutput = passkeyPrfOutput(credential);
  try {
    await api('/api/vault-passkeys/unlock/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challengeId: started.challengeId, response: credentialResponseForServer(credential) })
    });
    vaultKey = await unlockVaultWithPasskey(prfOutput, passkey);
  } finally {
    prfOutput.fill(0);
  }
  me = await api('/api/me');
  renderVaultStatus();
  await loadFiles();
  revealFilesAfterUnlock();
  await refreshRemoteUploads();
  resolvePendingVaultUnlock();
  showToast('加密空间已通过 Passkey 解锁');
}

async function loginWithPasskey() {
  if (!webauthnSupported()) throw new Error('当前浏览器不支持 Passkey');
  const started = await api('/api/passkey-login/options', { method: 'POST' });
  const credential = await navigator.credentials.get({
    publicKey: authenticationOptionsForBrowser(started.options)
  });
  if (!credential) throw new Error('未选择 Passkey');

  let prfOutput = null;
  try {
    prfOutput = passkeyPrfOutput(credential);
  } catch {
    // Older credentials can still log into the account but cannot derive the vault key.
  }

  let unlockedKey = null;
  try {
    const verified = await api('/api/passkey-login/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        challengeId: started.challengeId,
        response: credentialResponseForServer(credential)
      })
    });
    if (prfOutput) {
      try {
        const account = await api('/api/me');
        const passkey = account.encryption?.passkeys?.find(item => item.credentialId === verified.credentialId);
        if (passkey) unlockedKey = await unlockVaultWithPasskey(prfOutput, passkey);
      } catch {
        // The signed Passkey is enough to log in even when its vault wrapper cannot unlock.
      }
    }
  } finally {
    prfOutput?.fill(0);
  }
  await loadSession({ key: unlockedKey });
  showToast(unlockedKey ? '已通过 Passkey 登录并解锁加密空间' : '已通过 Passkey 登录，请解锁加密空间');
}

async function passkeyMaterialForPasskeyReset(purpose) {
  if (!webauthnSupported()) throw new Error('当前浏览器不支持 Passkey');
  const started = await api('/api/vault-passkeys/unlock/options', { method: 'POST' });
  const credential = await navigator.credentials.get({ publicKey: authenticationOptionsForBrowser(started.options) });
  if (!credential) throw new Error('未选择 Passkey');
  const passkey = me?.encryption?.passkeys?.find(item => item.credentialId === credential.id);
  if (!passkey) throw new Error('所选 Passkey 不属于当前账户');
  const prfOutput = passkeyPrfOutput(credential);
  try {
    const verified = await api('/api/vault-passkeys/unlock/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        challengeId: started.challengeId,
        response: credentialResponseForServer(credential),
        ...(purpose === 'recovery' ? { grantRecoveryReset: true } : { grantVaultKeyReset: true })
      })
    });
    const passkeyProof = purpose === 'recovery' ? verified.recoveryResetProof : verified.vaultKeyResetProof;
    if (!passkeyProof) throw new Error('Passkey 验证未完成');
    return {
      rawVaultKey: await unwrapVaultWithPasskey(prfOutput, passkey),
      passkeyProof
    };
  } finally {
    prfOutput.fill(0);
  }
}

async function verifyAccountDeletionWithPasskey() {
  if (!accountHasUsablePasskey()) throw new Error('当前浏览器没有可用于此账户的 Passkey');
  const started = await api('/api/passkey-actions/account-deletion/options', { method: 'POST' });
  const credential = await navigator.credentials.get({
    publicKey: authenticationOptionsForBrowser(started.options)
  });
  if (!credential) throw new Error('未选择 Passkey');
  const verified = await api('/api/passkey-actions/account-deletion/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      challengeId: started.challengeId,
      response: credentialResponseForServer(credential)
    })
  });
  if (!verified.passkeyProof) throw new Error('Passkey 验证未完成');
  return verified.passkeyProof;
}

async function verifyVaultPasskeyManagement({ requireVaultKey = false } = {}) {
  if (!vaultHasUsablePasskey()) throw new Error('当前浏览器没有可用于此账户的 Passkey');
  const started = await api('/api/passkey-actions/passkey-management/options', { method: 'POST' });
  const credential = await navigator.credentials.get({
    publicKey: authenticationOptionsForBrowser(started.options)
  });
  if (!credential) throw new Error('未选择 Passkey');
  const passkey = me?.encryption?.passkeys?.find(item => item.credentialId === credential.id);
  if (!passkey) throw new Error('所选 Passkey 不属于当前账户');
  let prfOutput = null;
  try {
    if (requireVaultKey) prfOutput = passkeyPrfOutput(credential);
    const verified = await api('/api/passkey-actions/passkey-management/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        challengeId: started.challengeId,
        response: credentialResponseForServer(credential)
      })
    });
    if (!verified.passkeyProof) throw new Error('Passkey 验证未完成');
    return {
      passkeyProof: verified.passkeyProof,
      rawVaultKey: requireVaultKey ? await unwrapVaultWithPasskey(prfOutput, passkey) : null
    };
  } finally {
    prfOutput?.fill(0);
  }
}

async function loadSession({ key } = {}) {
  stopRemoteUploadPolling();
  clearPreviewChunkCache();
  lockedListingCollapsed = false;
  currentDirectory = '';
  knownFolders = [];
  encryptedFolderRecordsByPath = new Map();
  selectedFileIds = new Set();
  closeFileManageModal();
  closePreviewModal();
  sessionLoading.hidden = false;
  authView.hidden = true;
  driveView.hidden = true;
  $('#account').hidden = true;
  me = null;
  vaultKey = null;
  try {
    me = await api('/api/me');
    if (key && me.encryption) vaultKey = key;
    $('#username').textContent = me.username;
    const avatarUrl = me.avatarUrl || '/li-bai-avatar.png';
    $('#accountAvatar').src = avatarUrl;
    $('#mobileAccountAvatar').src = avatarUrl;
    updateStorage();
    renderVaultStatus();
    try {
      await loadFiles();
      await refreshRemoteUploads();
    } catch {
      showToast('文件列表加载失败，请稍后刷新');
    }
    driveView.hidden = false;
    $('#account').hidden = false;
    startRemoteUploadPolling();
    startYuniSharePolling();
    openPendingMembershipMagicLink();
  } catch {
    me = null;
    vaultKey = null;
    authView.hidden = false;
    driveView.hidden = true;
    $('#account').hidden = true;
  } finally {
    sessionLoading.hidden = true;
  }
}

function updateStorage() {
  const percent = Math.min(100, me.used / me.quota * 100) || 0;
  $('#storageText').textContent = formatBytes(me.used) + ' / ' + formatBytes(me.quota);
  $('#storagePercent').textContent = percent.toFixed(1) + '%';
  $('#storageBar').style.width = percent + '%';
  const notice = $('#storageRetentionNotice');
  const retention = me.storageRetention;
  notice.hidden = !retention?.active;
  if (retention?.active) {
    const deadline = new Intl.DateTimeFormat('zh-CN', {
      year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit'
    }).format(new Date(retention.deadlineAt));
    setTrustedHtml(notice, '<strong>付费空间已到期 · 当前为下载保留期</strong><span>当前超出免费配额 ' + escapeHtml(formatBytes(retention.excessBytes)) + '。你仍可解锁、预览、下载和删除文件，但无法继续超额上传。请在 ' + escapeHtml(deadline) + ' 前续费或将用量降至 ' + escapeHtml(formatBytes(me.quota)) + ' 内；届时系统会从最新上传的完整文件开始删除，直到用量不再超额。</span>');
  }
  const uploadBlocked = me.used >= me.quota;
  $('#fileInput').disabled = uploadBlocked;
  $('#folderInput').disabled = uploadBlocked;
  $('#pickFiles').disabled = uploadBlocked;
  $('#pickFolder').disabled = uploadBlocked;
  for (const label of document.querySelectorAll('label[for="fileInput"], label[for="folderInput"]')) {
    label.classList.toggle('is-disabled', uploadBlocked);
    label.setAttribute('aria-disabled', String(uploadBlocked));
  }
  $('#dropZone').classList.toggle('is-disabled', uploadBlocked);
  $('#dropZone').setAttribute('aria-disabled', String(uploadBlocked));
}

function fileCategory(name = '', mime = '') {
  const extension = String(name).split('.').pop()?.toLowerCase() || '';
  const normalizedMime = String(mime).toLowerCase();
  if (normalizedMime.startsWith('image/') || ['jpg', 'jpeg', 'png', 'gif', 'webp', 'avif', 'heic', 'heif', 'bmp', 'tif', 'tiff', 'svg'].includes(extension)) return 'image';
  if (normalizedMime.startsWith('video/') || ['mp4', 'm4v', 'webm', 'mov', 'mkv', 'avi', 'ogv', 'flv', 'wmv'].includes(extension)) return 'video';
  if (normalizedMime.startsWith('audio/') || ['mp3', 'wav', 'aac', 'm4a', 'flac', 'ogg', 'oga', 'opus', 'aiff'].includes(extension)) return 'audio';
  if (normalizedMime === 'application/pdf' || extension === 'pdf') return 'pdf';
  if (['xls', 'xlsx', 'xlsm', 'ods', 'csv', 'tsv'].includes(extension)) return 'spreadsheet';
  if (['ppt', 'pptx', 'pptm', 'odp', 'key'].includes(extension)) return 'presentation';
  if (['zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz', 'tgz', 'tbz', 'zst'].includes(extension)) return 'archive';
  if (['doc', 'docx', 'odt', 'rtf', 'txt', 'md', 'markdown', 'pages', 'epub'].includes(extension)) return 'document';
  if (normalizedMime.startsWith('text/') || ['js', 'mjs', 'cjs', 'ts', 'tsx', 'jsx', 'html', 'htm', 'css', 'json', 'xml', 'yaml', 'yml', 'py', 'java', 'c', 'cpp', 'h', 'hpp', 'go', 'rs', 'sh', 'ps1', 'sql', 'vue', 'svelte'].includes(extension)) return 'code';
  return 'other';
}

function listingCategory(value) {
  return ['image', 'video', 'audio', 'pdf', 'document', 'spreadsheet', 'presentation', 'archive', 'code', 'other'].includes(value)
    ? value
    : 'other';
}

function fileCategoryLabel(category) {
  return ({ image: '图片', video: '视频', audio: '音频', pdf: 'PDF 文档', document: '文档', spreadsheet: '表格', presentation: '演示文稿', archive: '压缩包', code: '代码文件', other: '文件' })[listingCategory(category)];
}

function fileIconMarkup(category, folder = false) {
  if (folder) return '<div class="file-icon file-icon-folder" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M3.5 6.5h6l2 2H20.5v10h-17z"/></svg></div>';
  const normalized = listingCategory(category);
  const paths = {
    image: '<rect x="3.5" y="4.5" width="17" height="15" rx="2"/><circle cx="9" cy="9.5" r="1.5"/><path d="M5.5 17l4.2-4.3 3.1 3 2.2-2.2 3.5 3.5"/>',
    video: '<rect x="3.5" y="5" width="17" height="14" rx="2"/><path d="M10 9l5 3-5 3z"/>',
    audio: '<path d="M10 18V7l8-2v11"/><circle cx="7.5" cy="18" r="2.5"/><circle cx="15.5" cy="16" r="2.5"/>',
    pdf: '<path d="M6 3.5h8l4 4V20.5H6zM14 3.5v4h4M8.5 15.5h7M8.5 12.5h7"/>',
    document: '<path d="M6 3.5h8l4 4V20.5H6zM14 3.5v4h4M8.5 12h7M8.5 15h7M8.5 18h5"/>',
    spreadsheet: '<rect x="4" y="4" width="16" height="16" rx="2"/><path d="M4 9h16M9 4v16M4 14h16M14 9v11"/>',
    presentation: '<path d="M4 5h16v11H4zM12 16v4M8 20h8M8 13l3-3 2 2 3-3"/>',
    archive: '<path d="M5 5h14v15H5zM5 9h14M10 5v4M12 11v5M10.5 16h3"/>',
    code: '<path d="M9 8l-4 4 4 4M15 8l4 4-4 4M13.5 5l-3 14"/>',
    other: '<path d="M6 3.5h8l4 4V20.5H6zM14 3.5v4h4"/>'
  };
  return '<div class="file-icon file-icon-' + normalized + '" aria-hidden="true"><svg viewBox="0 0 24 24">' + paths[normalized] + '</svg></div>';
}

function formatPriceCents(cents) {
  return new Intl.NumberFormat('zh-CN', { minimumFractionDigits: 0, maximumFractionDigits: 2 }).format(Number(cents) / 100);
}

async function presentFile(file) {
  if (file.encryption_version !== ENCRYPTION_VERSION) {
    return { file, name: file.original_name, path: '', pathKnown: true, type: file.mime_type, category: fileCategory(file.original_name, file.mime_type), size: file.size, encrypted: false, locked: false };
  }
  if (!vaultKey) return {
    file,
    name: '加密文件',
    path: '',
    pathKnown: false,
    type: '',
    category: listingCategory(file.listing_category),
    size: file.plain_size ?? file.size,
    encrypted: true,
    locked: true
  };
  try {
    const metadata = await decryptMetadata(file);
    const presented = {
      file,
      name: metadata.name,
      path: normalizeFolderPath(metadata.path),
      pathKnown: true,
      type: metadata.mime || 'application/octet-stream',
      category: fileCategory(metadata.name, metadata.mime),
      size: metadata.size,
      encrypted: true,
      locked: false
    };
    metadata.fileKey = '';
    metadata.fileNonce = '';
    return presented;
  } catch {
    return { file, name: '无法解密的文件', path: '', pathKnown: false, type: '', category: 'other', size: file.plain_size ?? file.size, encrypted: true, locked: true, invalid: true };
  }
}

function folderPrefixes(folderPath) {
  const parts = normalizeFolderPath(folderPath).split('/').filter(Boolean);
  return parts.map((_, index) => parts.slice(0, index + 1).join('/'));
}

function renderFolderBreadcrumb() {
  const parts = currentDirectory.split('/').filter(Boolean);
  $('#folderBreadcrumb').hidden = parts.length === 0;
  if (!parts.length) {
    setTrustedHtml($('#folderBreadcrumb'), '');
    $('#currentFolderTitle').textContent = '全部文件';
    return;
  }
  let path = '';
  const crumbs = ['<button type="button" data-folder-path="">全部文件</button>'];
  for (const part of parts) {
    path = joinFolderPath(path, part);
    crumbs.push('<i aria-hidden="true">/</i><button type="button" data-folder-path="' + escapeHtml(path) + '">' + escapeHtml(part) + '</button>');
  }
  setTrustedHtml($('#folderBreadcrumb'), crumbs.join(''));
  $('#currentFolderTitle').textContent = parts.length ? parts.at(-1) : '全部文件';
}

function folderFileIds(folderPath) {
  return [...listedFiles.values()]
    .filter(item => item.path === folderPath || item.path.startsWith(folderPath + '/'))
    .map(item => item.file.id);
}

function fileActionsMarkup(actions, menuLabel = '更多操作') {
  return '<div class="file-actions"><div class="file-actions-desktop">' + actions + '</div><details class="file-actions-mobile" name="share-action-menu"><summary aria-label="' + escapeHtml(menuLabel) + '" title="' + escapeHtml(menuLabel) + '"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="5" cy="12" r="1.5"/><circle cx="12" cy="12" r="1.5"/><circle cx="19" cy="12" r="1.5"/></svg><span>更多</span></summary><div class="file-actions-menu">' + actions + '</div></details></div>';
}

function closeShareActionMenus(except = null) {
  document.querySelectorAll('details.file-actions-mobile[open]').forEach(menu => {
    if (menu !== except) menu.removeAttribute('open');
  });
}

function renderFolderRow(folderPath, displayFiles) {
  const name = folderPath.split('/').at(-1);
  const ids = displayFiles.filter(item => item.path === folderPath || item.path.startsWith(folderPath + '/')).map(item => item.file.id);
  const normalized = normalizeFolderPath(folderPath);
  const selected = selectedFolderPaths.has(normalized) || (ids.length > 0 && ids.every(id => selectedFileIds.has(id)));
  const actions = '<button type="button" class="icon-button rename-folder" data-folder-path="' + escapeHtml(folderPath) + '" data-name="' + escapeHtml(name) + '" title="重命名文件夹" aria-label="重命名文件夹 ' + escapeHtml(name) + '"><svg viewBox="0 0 24 24"><path d="M12 20h9M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg><span class="file-action-label">重命名</span></button><button type="button" class="icon-button move-folder" data-folder-path="' + escapeHtml(folderPath) + '" title="移动文件夹" aria-label="移动文件夹 ' + escapeHtml(name) + '"><svg viewBox="0 0 24 24"><path d="M3 7h7l2 2h9v10H3zM9 14h7M13 11l3 3-3 3"/></svg><span class="file-action-label">移动</span></button><button type="button" class="icon-button danger delete-folder" data-folder-path="' + escapeHtml(folderPath) + '" data-name="' + escapeHtml(name) + '" title="删除文件夹" aria-label="删除文件夹 ' + escapeHtml(name) + '"><svg viewBox="0 0 24 24"><path d="M4 7h16M9 7V4h6v3M7 7l1 13h8l1-13M10 11v5M14 11v5"/></svg><span class="file-action-label">删除</span></button>';
  return '<div class="file-row folder-row' + (selected ? ' is-selected' : '') + '"><button class="file-select folder-select" type="button" role="checkbox" aria-checked="' + selected + '" data-folder-path="' + escapeHtml(folderPath) + '" aria-label="选择文件夹 ' + escapeHtml(name) + '"></button>' + fileIconMarkup('other', true) + '<button type="button" class="folder-open file-info" data-folder-path="' + escapeHtml(folderPath) + '"><span class="file-name" title="' + escapeHtml(name) + '">' + escapeHtml(name) + '</span><span class="file-meta">' + ids.length + ' 个文件 · 路径信息已端到端加密</span></button>' + fileActionsMarkup(actions, '文件夹更多操作') + '</div>';
}

function renderFileRow(item) {
  const name = escapeHtml(item.name);
  const status = item.locked
    ? '<span class="locked-file">内容已锁定 · 解锁后显示原始名称</span>'
    : item.encrypted
      ? '<span class="e2ee-file">端到端加密</span>'
      : '<span class="legacy-file">旧格式</span>';
  const download = item.encrypted
    ? '<button class="icon-button download-file" data-id="' + item.file.id + '" title="解密并下载" aria-label="解密并下载 ' + name + '"' + (item.locked ? ' disabled' : '') + '><svg viewBox="0 0 24 24"><path d="M12 4v12M7 11l5 5 5-5M5 20h14"/></svg><span class="file-action-label">下载</span></button>'
    : '<a class="icon-button" href="/api/files/' + item.file.id + '/download" title="下载" aria-label="下载 ' + name + '"><svg viewBox="0 0 24 24"><path d="M12 4v12M7 11l5 5 5-5M5 20h14"/></svg><span class="file-action-label">下载</span></a>';
  const manage = item.encrypted && !item.locked
    ? '<button class="icon-button preview-file" data-id="' + item.file.id + '" title="预览" aria-label="预览 ' + name + '"><svg viewBox="0 0 24 24"><path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6S2.5 12 2.5 12z"/><circle cx="12" cy="12" r="2.5"/></svg><span class="file-action-label">预览</span></button><button class="icon-button rename-file" data-id="' + item.file.id + '" title="重命名" aria-label="重命名 ' + name + '"><svg viewBox="0 0 24 24"><path d="M4 20h4l11-11-4-4L4 16v4zM13 7l4 4"/></svg><span class="file-action-label">重命名</span></button><button class="icon-button move-file" data-id="' + item.file.id + '" title="移动" aria-label="移动 ' + name + '"><svg viewBox="0 0 24 24"><path d="M3 7h7l2 2h9v10H3zM9 14h7M13 11l3 3-3 3"/></svg><span class="file-action-label">移动</span></button>'
    : '';
  const selected = selectedFileIds.has(item.file.id);
  const actions = download + manage + '<button class="icon-button danger delete-file" data-id="' + item.file.id + '" data-name="' + name + '" title="删除" aria-label="删除 ' + name + '"><svg viewBox="0 0 24 24"><path d="M4 7h16M9 7V4h6v3M7 7l1 13h8l1-13M10 11v5M14 11v5"/></svg><span class="file-action-label">删除</span></button>';
  return '<div class="file-row' + (selected ? ' is-selected' : '') + '"><button class="file-select" type="button" role="checkbox" aria-checked="' + selected + '" data-file-id="' + item.file.id + '" aria-label="选择文件 ' + name + '"></button>' + fileIconMarkup(item.category) + '<div class="file-info"><span class="file-name" title="' + name + '">' + name + '</span><span class="file-meta">' + formatBytes(item.size) + ' · ' + formatDate(item.file.created_at) + ' · ' + status + '</span></div>' + fileActionsMarkup(actions, '文件更多操作') + '</div>';
}

function renderLockedCollectionRows(displayFiles, encryptedFolders) {
  const hasClassifiedFolders = encryptedFolders.some(folder => folder.is_root === 0 || folder.is_root === 1);
  const rootFolders = encryptedFolders.filter(folder => folder.is_root === 1);
  const visibleFolders = rootFolders.length
    ? rootFolders
    : (!hasClassifiedFolders && encryptedFolders.length ? [encryptedFolders[0]] : []);
  const suppressUnknownFiles = encryptedFolders.length > 0 && !hasClassifiedFolders;
  const visibleFiles = displayFiles.filter(item => item.file.inside_folder === 0
    || (item.file.inside_folder == null && !suppressUnknownFiles));
  const folderRows = visibleFolders.map(folder =>
    '<div class="file-row folder-row locked-collection-row" data-locked-folder-id="' + escapeHtml(folder.id) + '">' + fileIconMarkup('other', true) + '<div class="file-info"><span class="file-name">加密文件夹</span><span class="file-meta">根文件夹 · 解锁后显示真实名称和内部结构</span></div></div>'
  );
  const fileRows = visibleFiles.map(item => {
    const category = listingCategory(item.category);
    return '<div class="file-row locked-collection-row" data-locked-file-id="' + escapeHtml(item.file.id) + '">' + fileIconMarkup(category) + '<div class="file-info"><span class="file-name">加密' + escapeHtml(fileCategoryLabel(category)) + '</span><span class="file-meta">' + escapeHtml(fileCategoryLabel(category)) + ' · 解锁后显示真实名称与内容</span></div></div>';
  });
  return { html: [...folderRows, ...fileRows].join(''), folderCount: folderRows.length, fileCount: fileRows.length };
}

async function decryptEncryptedFolderRecords(records) {
  if (!vaultKey) return [];
  const decrypted = await Promise.all(records.map(async record => {
    try { return { ...(await decryptFolderMetadata(record)), source: record }; } catch { return null; }
  }));
  return decrypted.filter(Boolean);
}

async function ensureEncryptedFolderRecords(folderPaths, byPath) {
  if (!vaultKey) return;
  await Promise.all(folderPaths.map(async folderPath => {
    const existing = byPath.get(folderPath);
    if (existing) return;
    const id = existing?.id || crypto.randomUUID();
    const encryption = await encryptFolderMetadata(id, folderPath);
    await api('/api/folders', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        id,
        isRoot: parentFolderPath(folderPath) === '',
        encryption: { version: ENCRYPTION_VERSION, ...encryption }
      })
    });
    byPath.set(folderPath, {
      id,
      path: folderPath,
      source: {
        id,
        encrypted_metadata: encryption.metadata,
        encrypted_metadata_iv: encryption.metadataIv,
        is_root: parentFolderPath(folderPath) === '' ? 1 : 0
      }
    });
  }));
}

async function syncEncryptedFolderRecords(knownFolders, decryptedFolderRecords) {
  if (!vaultKey) return;
  const allCurrentFolders = new Set(knownFolders);

  const recordsByPath = new Map();
  const duplicateIdsToDelete = [];

  for (const record of (decryptedFolderRecords || [])) {
    if (!allCurrentFolders.has(record.path)) {
      duplicateIdsToDelete.push(record.id);
    } else if (recordsByPath.has(record.path)) {
      duplicateIdsToDelete.push(record.id);
    } else {
      recordsByPath.set(record.path, record);
    }
  }

  if (duplicateIdsToDelete.length) {
    await api('/api/folders/batch-delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: duplicateIdsToDelete })
    }).catch(() => {});
  }

  for (const folderPath of knownFolders) {
    const isRoot = parentFolderPath(folderPath) === '';
    const existing = recordsByPath.get(folderPath);
    if (!existing) {
      const id = crypto.randomUUID();
      const encryption = await encryptFolderMetadata(id, folderPath);
      await api('/api/folders', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id,
          isRoot,
          encryption: { version: ENCRYPTION_VERSION, ...encryption }
        })
      }).catch(() => {});
      recordsByPath.set(folderPath, {
        id,
        path: folderPath,
        source: {
          id,
          encrypted_metadata: encryption.metadata,
          encrypted_metadata_iv: encryption.metadataIv,
          is_root: isRoot ? 1 : 0
        }
      });
    } else if (existing.source && existing.source.is_root !== (isRoot ? 1 : 0)) {
      await api('/api/folders/' + existing.id, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ isRoot })
      }).catch(() => {});
      existing.source.is_root = isRoot ? 1 : 0;
    }
  }

  encryptedFolderRecordsByPath = recordsByPath;
}

async function syncFileListingHints(displayFiles) {
  if (!vaultKey) return;
  const hints = displayFiles.filter(item => item.encrypted && !item.locked).map(item => ({
    id: item.file.id,
    category: listingCategory(item.category),
    insideFolder: Boolean(item.path)
  }));
  if (!hints.length) return;
  await api('/api/files/listing-hints', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ hints })
  });
}

function currentDirectoryFileIds() {
  return [...listedFiles.values()]
    .filter(item => !currentDirectory || item.path === currentDirectory || item.path.startsWith(currentDirectory + '/'))
    .map(item => item.file.id);
}

function updateBatchToolbar() {
  const existingIds = new Set(listedFiles.keys());
  selectedFileIds = new Set([...selectedFileIds].filter(id => existingIds.has(id)));
  const visibleIds = currentDirectoryFileIds();
  const selectedVisible = visibleIds.filter(id => selectedFileIds.has(id));
  const checkbox = $('#selectVisibleFiles');
  checkbox.checked = visibleIds.length > 0 && selectedVisible.length === visibleIds.length;
  checkbox.indeterminate = selectedVisible.length > 0 && selectedVisible.length < visibleIds.length;
  checkbox.disabled = visibleIds.length === 0;
  const totalSelected = selectedFileIds.size + (selectedFolderPaths ? selectedFolderPaths.size : 0);
  $('#fileBatchToolbar').hidden = listedFiles.size === 0 || lockedListingCollapsed;
  $('#selectedFileCount').textContent = '已选择 ' + (selectedFileIds.size ? selectedFileIds.size + ' 个文件' : '') + (selectedFolderPaths && selectedFolderPaths.size ? (selectedFileIds.size ? ' · ' : '') + selectedFolderPaths.size + ' 个文件夹' : (selectedFileIds.size ? '' : '0 个项目'));
  $('#downloadSelectedFiles').disabled = selectedFileIds.size === 0 || !vaultKey;
  $('#deleteSelectedFiles').disabled = totalSelected === 0;
}

function selectionIdsForControl(control) {
  return control.dataset.folderPath
    ? folderFileIds(normalizeFolderPath(control.dataset.folderPath))
    : [control.dataset.fileId];
}

function syncRenderedSelectionControls() {
  const controls = [...document.querySelectorAll('#fileList .file-select')];
  const folderStates = new Map(controls.filter(control => control.dataset.folderPath).map(control => [
    normalizeFolderPath(control.dataset.folderPath),
    { total: 0, selected: 0 }
  ]));
  for (const item of listedFiles.values()) {
    let folderPath = item.path;
    while (folderPath) {
      const state = folderStates.get(folderPath);
      if (state) {
        state.total += 1;
        if (selectedFileIds.has(item.file.id)) state.selected += 1;
      }
      folderPath = parentFolderPath(folderPath);
    }
  }
  for (const control of controls) {
    if (control.dataset.folderPath) {
      const folderPath = normalizeFolderPath(control.dataset.folderPath);
      const state = folderStates.get(folderPath);
      const selected = selectedFolderPaths.has(folderPath) || (state && state.total > 0 && state.selected === state.total);
      control.setAttribute('aria-checked', String(selected));
      control.closest('.file-row')?.classList.toggle('is-selected', selected);
    } else {
      const selected = selectedFileIds.has(control.dataset.fileId);
      control.setAttribute('aria-checked', String(selected));
      control.closest('.file-row')?.classList.toggle('is-selected', selected);
    }
  }
  updateBatchToolbar();
}

// The search index lives only in this unlocked page, never in browser storage.
const explorerIndex = new Map();
const explorerRows = new Map();
let explorerDescending = false;
const explorerCollator = new Intl.Collator(undefined, {numeric:true,sensitivity:'base'});
const propertyDialog = document.createElement('dialog');
propertyDialog.className = 'explorer-properties';
propertyDialog.setAttribute('aria-label','文件属性');
document.body.append(propertyDialog);
function clearExplorerPrivateState() {
  explorerIndex.clear(); explorerRows.clear();
  $('#explorerSearch').value = '';
  $('#explorerResult').textContent = '';
  propertyDialog.close(); propertyDialog.replaceChildren();
}
function propertyButton(id, folder = false) {
  return '<button type="button" class="icon-button explorer-property" data-property-' + (folder?'folder':'id') + '="' + escapeHtml(id) + '" title="属性" aria-label="属性"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7v1"/></svg><span class="file-action-label">属性</span></button>';
}
function renderExplorer() {
  if (!vaultKey) {clearExplorerPrivateState();return;}
  const all = [...listedFiles.values()];
  const tokens = $('#explorerSearch').value.trim().normalize('NFKC').toLocaleLowerCase().split(/\s+/).filter(Boolean);
  const active = new Set();
  for (const item of all) {
    const id = item.file.id, source = item.path+'\n'+item.name;
    active.add(id);
    if (explorerIndex.get(id)?.source !== source) explorerIndex.set(id,{source,text:source.normalize('NFKC').toLocaleLowerCase()});
  }
  for (const id of explorerIndex.keys()) if (!active.has(id)) explorerIndex.delete(id);
  const matches = text => tokens.every(token => text.includes(token));
  const key = $('#explorerSort').value;
  const direction = explorerDescending ? -1 : 1;
  const aggregates = new Map();
  for (const item of all) for (const path of folderPrefixes(item.path)) {
    const sum = aggregates.get(path) || {size:0,time:0};
    sum.size += Number(item.size)||0;sum.time=Math.max(sum.time,Number(item.file.created_at)||0);aggregates.set(path,sum);
  }
  const compare = (a,b) => direction * ((key==='name' ? explorerCollator.compare(a.name,b.name) : a[key]-b[key]) || explorerCollator.compare(a.id,b.id));
  const folders = knownFolders.filter(path => tokens.length ? matches(path.normalize('NFKC').toLocaleLowerCase()) : parentFolderPath(path)===currentDirectory)
    .map(path=>({id:path,name:path.split('/').at(-1),...(aggregates.get(path)||{size:0,time:0})})).sort(compare);
  const files = all.filter(item => tokens.length ? matches(explorerIndex.get(item.file.id).text) : item.path===currentDirectory)
    .map(item=>({id:item.file.id,name:item.name,size:Number(item.size)||0,time:Number(item.file.created_at)||0,item})).sort(compare);
  const rows = [...folders.map(folder=>({key:'folder:'+folder.id,html:renderFolderRow(folder.id,all),property:propertyButton(folder.id,true)})),
    ...files.map(({item})=>({key:'file:'+item.file.id,html:renderFileRow(item),property:propertyButton(item.file.id)}))];
  const list=$('#fileList'), keep=new Set(rows.map(row=>row.key));
  for (const [id,record] of explorerRows) if (!keep.has(id)) {record.node.remove();explorerRows.delete(id);}
  let cursor=list.firstChild;
  for (const row of rows) {
    let record=explorerRows.get(row.key);
    if (!record || record.html!==row.html) {
      const holder=document.createElement('div');setTrustedHtml(holder,row.html);
      const node=holder.firstElementChild;
      for (const target of node.querySelectorAll('.file-actions-desktop,.file-actions-menu')) {
        const action=document.createElement('div');setTrustedHtml(action,row.property);target.append(action.firstElementChild);
      }
      if(record?.node===cursor) cursor=cursor.nextSibling;
      record?.node.remove();record={html:row.html,node};explorerRows.set(row.key,record);
    }
    if(record.node!==cursor) list.insertBefore(record.node,cursor); else cursor=cursor.nextSibling;
  }
  while(cursor) {const next=cursor.nextSibling;cursor.remove();cursor=next;}
  renderFolderBreadcrumb();
  $('#fileCount').textContent=all.length+' 个文件';
  $('#explorerResult').textContent=tokens.length ? rows.length+' 项结果 · 所有目录' : rows.length+' 项 · 当前目录';
  $('#emptyState').hidden=rows.length>0;
  $('#emptyState strong').textContent=tokens.length?'没有匹配的文件':'这里还没有文件';
  $('#emptyState span').textContent=tokens.length?'试试其他名称、路径或文件后缀':'上传图片、视频或其他文件开始使用';
  updateBatchToolbar();
}
$('#explorerSearch').addEventListener('input',renderExplorer);
$('#explorerSort').addEventListener('change',renderExplorer);
$('#explorerDirection').addEventListener('click',()=>{explorerDescending=!explorerDescending;$('#explorerDirection').textContent=explorerDescending?'降序 ↓':'升序 ↑';renderExplorer();});
$('#fileList').addEventListener('click',event=>{
  const button=event.target.closest('.explorer-property');if(!button)return;
  const item=listedFiles.get(button.dataset.propertyId), folder=button.dataset.propertyFolder;
  if(!vaultKey || (!item && folder===undefined))return;
  const members=folder===undefined?[]:[...listedFiles.values()].filter(item=>item.path===folder || item.path.startsWith(folder+'/'));
  const fields=folder===undefined ? [
    ['名称',item.name],['类型',item.name.includes('.')?item.name.split('.').at(-1).toUpperCase()+' 文件':'文件'],
    ['位置',item.path||'根目录'],['大小',formatBytes(item.size)+' ('+Number(item.size).toLocaleString()+' 字节)'],
    ['上传时间',formatDate(item.file.created_at)],['加密状态',item.encrypted?'端到端加密':'旧格式'],['文件 ID',item.file.id]
  ] : [['名称',folder.split('/').at(-1)],['类型','文件夹'],['位置',parentFolderPath(folder)||'根目录'],['包含',members.length+' 个文件'],['总大小',formatBytes(members.reduce((n,item)=>n+Number(item.size||0),0))],['加密状态','端到端加密']];
  propertyDialog.replaceChildren();
  const title=document.createElement('h2');title.textContent='属性';propertyDialog.append(title);
  const list=document.createElement('dl');
  for(const [label,value] of fields) {const dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=label;dd.textContent=value;list.append(dt,dd);}
  propertyDialog.append(list);
  const close=document.createElement('button');close.textContent='关闭';close.type='button';close.addEventListener('click',()=>propertyDialog.close());propertyDialog.append(close);
  propertyDialog.showModal();
});

async function loadFiles() {
  const response = await api('/api/files');
  const encryptedFolders = Array.isArray(response.folders) ? response.folders : [];
  const displayFiles = await Promise.all(response.files.map(presentFile));
  listedFiles = new Map(displayFiles.map(item => [item.file.id, item]));
  lockedListingCollapsed = !vaultKey && (displayFiles.length > 0 || encryptedFolders.length > 0);
  if (lockedListingCollapsed) {
    clearExplorerPrivateState();
    currentDirectory = '';
    knownFolders = [];
    encryptedFolderRecordsByPath = new Map();
    selectedFileIds = new Set();
    renderFolderBreadcrumb();
    const lockedRows = renderLockedCollectionRows(displayFiles, encryptedFolders);
    $('#fileCount').textContent = lockedRows.folderCount + ' 个文件夹 · ' + lockedRows.fileCount + ' 个文件';
    $('#emptyState').hidden = lockedRows.folderCount > 0 || lockedRows.fileCount > 0;
    setTrustedHtml($('#fileList'), lockedRows.html);
    updateBatchToolbar();
    return;
  }
  const decryptedFolderRecords = await decryptEncryptedFolderRecords(encryptedFolders);
  encryptedFolderRecordsByPath = new Map(decryptedFolderRecords.map(record => [record.path, record]));
  knownFolders = [...new Set([
    ...displayFiles.flatMap(item => folderPrefixes(item.path)),
    ...decryptedFolderRecords.flatMap(record => folderPrefixes(record.path))
  ])].sort((left, right) => left.localeCompare(right, 'zh-CN'));
  await Promise.all([
    syncEncryptedFolderRecords(knownFolders, decryptedFolderRecords),
    syncFileListingHints(displayFiles)
  ]).catch(() => {});
  if (currentDirectory && !knownFolders.includes(currentDirectory)) currentDirectory = '';
  renderExplorer();
  void prefetchPreviewChunks([...listedFiles.values()].filter(item=>item.path===currentDirectory));
}

function revealFilesAfterUnlock() {
  if (!window.matchMedia('(max-width: 760px)').matches) return;
  requestAnimationFrame(() => {
    $('#filesSection')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
}

function closeFileManageModal() {
  $('#fileManageModal').hidden = true;
  $('#fileManageError').textContent = '';
  $('#fileRenameInput').value = '';
  managedFileId = '';
  managedFolderPath = '';
}

function openFileManageModal(mode, fileId) {
  const item = listedFiles.get(fileId);
  if (!vaultKey || !item?.encrypted || item.locked) {
    showToast('请先解锁端到端加密空间');
    return;
  }
  managedFileId = fileId;
  $('#fileManageModal').dataset.mode = mode;
  $('#fileRenameField').hidden = mode !== 'rename';
  $('#fileMoveField').hidden = mode !== 'move';
  $('#fileManageTitle').textContent = mode === 'rename' ? '重命名文件' : '移动文件';
  $('#fileManageCopy').textContent = mode === 'rename'
    ? '新名称会在当前浏览器中加密，文件内容无需重新上传。'
    : '目标目录会写入端到端加密元数据，服务器无法读取目录结构。';
  $('#fileManageSubmit').textContent = mode === 'rename' ? '保存名称' : '移动文件';
  $('#fileManageError').textContent = '';
  if (mode === 'rename') {
    const ext = extractFileExtension(item.name);
    const baseName = ext ? item.name.slice(0, -ext.length) : item.name;
    $('#fileRenameInput').value = item.name;
    $('#fileRenameInput').required = true;
    requestAnimationFrame(() => {
      $('#fileRenameInput').focus();
      if (ext && item.name.endsWith(ext)) {
        $('#fileRenameInput').setSelectionRange(0, baseName.length);
      } else {
        $('#fileRenameInput').select();
      }
    });
  } else {
    $('#fileRenameInput').required = false;
    const select = $('#fileMoveSelect');
    select.replaceChildren();
    select.append(new Option('全部文件（根目录）', ''));
    for (const folderPath of knownFolders) select.append(new Option(folderPath, folderPath));
    select.value = item.path;
  }
  $('#fileManageModal').hidden = false;
  (mode === 'rename' ? $('#fileRenameInput') : $('#fileMoveSelect')).focus();
}

function openFolderRenameModal(folderPath) {
  if (!vaultKey) {
    openVaultModal('unlock');
    return;
  }
  managedFileId = '';
  managedFolderPath = normalizeFolderPath(folderPath);
  if (!managedFolderPath || !knownFolders.includes(managedFolderPath)) return;
  const folderName = managedFolderPath.split('/').at(-1);
  $('#fileManageModal').dataset.mode = 'rename-folder';
  $('#fileRenameField').hidden = false;
  $('#fileMoveField').hidden = true;
  $('#fileRenameInput').required = true;
  $('#fileRenameInput').value = folderName;
  $('#fileManageTitle').textContent = '重命名文件夹';
  $('#fileManageCopy').textContent = '文件夹及其内部文件的元数据会在当前浏览器中重新加密，文件内容和存储对象无需移动。';
  $('#fileManageSubmit').textContent = '保存名称';
  $('#fileManageError').textContent = '';
  $('#fileManageModal').hidden = false;
  $('#fileRenameInput').focus();
}

function openFolderMoveModal(folderPath) {
  if (!vaultKey) {
    openVaultModal('unlock');
    return;
  }
  managedFileId = '';
  managedFolderPath = normalizeFolderPath(folderPath);
  if (!managedFolderPath || !knownFolders.includes(managedFolderPath)) return;
  $('#fileManageModal').dataset.mode = 'move-folder';
  $('#fileRenameField').hidden = true;
  $('#fileMoveField').hidden = false;
  $('#fileRenameInput').required = false;
  $('#fileManageTitle').textContent = '移动文件夹';
  $('#fileManageCopy').textContent = '文件夹及其内部文件的目录元数据会在当前浏览器中重新加密，文件内容和存储对象无需移动。';
  $('#fileManageSubmit').textContent = '移动文件夹';
  $('#fileManageError').textContent = '';
  const select = $('#fileMoveSelect');
  select.replaceChildren();
  select.append(new Option('全部文件（根目录）', ''));
  for (const candidate of knownFolders) {
    if (candidate === managedFolderPath || candidate.startsWith(managedFolderPath + '/')) continue;
    select.append(new Option(candidate, candidate));
  }
  select.value = parentFolderPath(managedFolderPath);
  $('#fileManageModal').hidden = false;
  select.focus();
}

async function updateEncryptedFileMetadata(item, changes) {
  if (!vaultKey) throw new Error('加密空间已锁定');
  const metadata = await decryptMetadata(item.file);
  const nextName = String(changes.name ?? metadata.name).trim();
  const nextPath = normalizeFolderPath(changes.path ?? metadata.path);
  if (!fileNameIsValid(nextName)) throw new Error('文件名不能为空，且不能包含斜杠或控制字符');
  metadata.name = nextName;
  metadata.path = nextPath;
  const encrypted = await encryptMetadata(item.file.upload_id || item.file.id, metadata);
  metadata.fileKey = '';
  metadata.fileNonce = '';
  await api('/api/files/' + item.file.id + '/metadata', {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
      encryption: { version: ENCRYPTION_VERSION, metadata: encrypted.metadata, metadataIv: encrypted.metadataIv }
    })
  });
}

async function updateEncryptedFolderMetadata(record, nextPath) {
  const encryption = await encryptFolderMetadata(record.id, nextPath);
  await api('/api/folders/' + record.id, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      isRoot: parentFolderPath(nextPath) === '',
      encryption: { version: ENCRYPTION_VERSION, ...encryption }
    })
  });
}

async function moveEncryptedFolder(folderPath, targetParent) {
  const sourcePath = normalizeFolderPath(folderPath);
  const destinationParent = normalizeFolderPath(targetParent);
  const folderName = sourcePath.split('/').at(-1);
  const destinationPath = joinFolderPath(destinationParent, folderName);
  if (!sourcePath || destinationPath === sourcePath) throw new Error('文件夹已经在这个目录中');
  if (destinationParent === sourcePath || destinationParent.startsWith(sourcePath + '/')) {
    throw new Error('不能把文件夹移动到自身或其子文件夹中');
  }
  
  // If destination exists, check if it has files
  const destFiles = folderFileIds(destinationPath);
  if (destFiles.length > 0) {
    throw new Error('目标位置已存在同名且包含文件的文件夹');
  }

  // If destination has an empty folder record, delete it so we can take over the path
  const destRecords = [...encryptedFolderRecordsByPath.values()].filter(record => record.path === destinationPath);
  if (destRecords.length) {
    const destIds = destRecords.map(r => r.id);
    await api('/api/folders/batch-delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: destIds })
    }).catch(() => {});
    for (const r of destRecords) encryptedFolderRecordsByPath.delete(r.path);
  }

  // 1. Move all files under sourcePath to destinationPath in 1 atomic parallel batch!
  const affectedFiles = [...listedFiles.values()].filter(item => item.path === sourcePath || item.path.startsWith(sourcePath + '/'));
  if (affectedFiles.length) {
    const fileUpdates = await Promise.all(affectedFiles.map(async item => {
      const suffix = item.path.slice(sourcePath.length).replace(/^\//, '');
      const newPath = joinFolderPath(destinationPath, suffix);
      const metadata = await decryptMetadata(item.file);
      metadata.path = newPath;
      const encrypted = await encryptMetadata(item.file.upload_id || item.file.id, metadata);
      metadata.fileKey = '';
      metadata.fileNonce = '';
      return {
        id: item.file.id,
        encryption: {
          version: ENCRYPTION_VERSION,
          metadata: encrypted.metadata,
          metadataIv: encrypted.metadataIv
        }
      };
    }));

    await api('/api/files/batch-metadata', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ updates: fileUpdates })
    });
  }

  // 2. Update or delete all folder records under sourcePath
  const affectedFolders = [...encryptedFolderRecordsByPath.values()]
    .filter(record => record.path === sourcePath || record.path.startsWith(sourcePath + '/'))
    .sort((left, right) => left.path.length - right.path.length);

  if (affectedFolders.length) {
    for (const record of affectedFolders) {
      const suffix = record.path.slice(sourcePath.length).replace(/^\//, '');
      const newPath = joinFolderPath(destinationPath, suffix);
      await updateEncryptedFolderMetadata(record, newPath);
    }
  }

  // 3. Clean up in-memory knownFolders and encryptedFolderRecordsByPath
  knownFolders = knownFolders.filter(p => p !== sourcePath && !p.startsWith(sourcePath + '/'));
  for (const record of affectedFolders) {
    encryptedFolderRecordsByPath.delete(record.path);
  }

  currentDirectory = destinationParent;
}

async function renameEncryptedFolder(folderPath, newName) {
  const sourcePath = normalizeFolderPath(folderPath);
  const nextName = String(newName || '').trim();
  if (!fileNameIsValid(nextName)) throw new Error('文件夹名称不能为空，且不能包含斜杠或控制字符');
  const currentName = sourcePath.split('/').at(-1);
  if (nextName === currentName) throw new Error('文件夹名称没有变化');

  const parentPath = parentFolderPath(sourcePath);
  const destinationPath = joinFolderPath(parentPath, nextName);

  const destFiles = folderFileIds(destinationPath);
  if (destFiles.length > 0) {
    throw new Error('目标位置已存在同名且包含文件的文件夹');
  }

  // If destination has an empty folder record, delete it
  const destRecords = [...encryptedFolderRecordsByPath.values()].filter(record => record.path === destinationPath);
  if (destRecords.length) {
    const destIds = destRecords.map(r => r.id);
    await api('/api/folders/batch-delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: destIds })
    }).catch(() => {});
    for (const r of destRecords) encryptedFolderRecordsByPath.delete(r.path);
  }

  // 1. Rename all files under sourcePath to destinationPath in 1 atomic parallel batch!
  const affectedFiles = [...listedFiles.values()].filter(item => item.path === sourcePath || item.path.startsWith(sourcePath + '/'));
  if (affectedFiles.length) {
    const fileUpdates = await Promise.all(affectedFiles.map(async item => {
      const suffix = item.path.slice(sourcePath.length).replace(/^\//, '');
      const newPath = joinFolderPath(destinationPath, suffix);
      const metadata = await decryptMetadata(item.file);
      metadata.path = newPath;
      const encrypted = await encryptMetadata(item.file.upload_id || item.file.id, metadata);
      metadata.fileKey = '';
      metadata.fileNonce = '';
      return {
        id: item.file.id,
        encryption: {
          version: ENCRYPTION_VERSION,
          metadata: encrypted.metadata,
          metadataIv: encrypted.metadataIv
        }
      };
    }));

    await api('/api/files/batch-metadata', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ updates: fileUpdates })
    });
  }

  // 2. Update folder records under sourcePath
  const affectedFolders = [...encryptedFolderRecordsByPath.values()]
    .filter(record => record.path === sourcePath || record.path.startsWith(sourcePath + '/'))
    .sort((left, right) => left.path.length - right.path.length);

  if (affectedFolders.length) {
    for (const record of affectedFolders) {
      const suffix = record.path.slice(sourcePath.length).replace(/^\//, '');
      const newPath = joinFolderPath(destinationPath, suffix);
      await updateEncryptedFolderMetadata(record, newPath);
    }
  }

  // 3. Clean up in-memory knownFolders and encryptedFolderRecordsByPath
  knownFolders = knownFolders.filter(p => p !== sourcePath && !p.startsWith(sourcePath + '/'));
  for (const record of affectedFolders) {
    encryptedFolderRecordsByPath.delete(record.path);
  }

  if (currentDirectory === sourcePath || currentDirectory.startsWith(sourcePath + '/')) {
    const suffix = currentDirectory.slice(sourcePath.length).replace(/^\//, '');
    currentDirectory = joinFolderPath(destinationPath, suffix);
  }
}

async function deleteEncryptedFolder(folderPath) {
  const normalized = normalizeFolderPath(folderPath);
  const ids = folderFileIds(normalized);
  if (ids.length) {
    await deleteFileIds(ids, { reload: false });
  }
  const records = [...encryptedFolderRecordsByPath.values()].filter(record =>
    record.path === normalized || record.path.startsWith(normalized + '/')
  );
  if (records.length) {
    const folderRecordIds = records.map(r => r.id);
    await api('/api/folders/batch-delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: folderRecordIds })
    }).catch(async () => {
      await Promise.all(records.map(record => api('/api/folders/' + record.id, { method: 'DELETE' }).catch(() => {})));
    });
  }
  knownFolders = knownFolders.filter(p => p !== normalized && !p.startsWith(normalized + '/'));
  for (const record of records) {
    encryptedFolderRecordsByPath.delete(record.path);
  }
  if (currentDirectory === normalized || currentDirectory.startsWith(normalized + '/')) {
    currentDirectory = parentFolderPath(normalized);
  }
  me = await api('/api/me');
  updateStorage();
  await loadFiles();
  return ids.length;
}

function closeCreateItemModal() {
  $('#createItemModal').hidden = true;
  $('#createItemError').textContent = '';
  $('#createItemName').value = '';
}

function openCreateItemModal(mode) {
  if (!vaultKey) {
    return;
  }
  $('#createItemModal').dataset.mode = mode;
  const folderMode = mode === 'folder';
  $('#createItemTitle').textContent = folderMode ? '新建文件夹' : '新建空文件';
  $('#createItemCopy').textContent = folderMode
    ? '空文件夹的名称和路径会在当前浏览器中加密后保存。'
    : '可自由指定扩展名（如 .txt、.md、.json、.py 等），文件从浏览器开始即为端到端加密。';
  $('#createItemNameLabel').firstChild.textContent = folderMode ? '文件夹名称' : '文件名称';
  $('#createItemName').value = folderMode ? '新建文件夹' : '新建文本文档.txt';
  $('#createItemError').textContent = '';
  $('#createItemSubmit').textContent = folderMode ? '创建文件夹' : '创建空文件';
  $('#createItemModal').hidden = false;
  $('#createItemName').focus();
  if (folderMode) {
    $('#createItemName').select();
  } else {
    const dotIndex = $('#createItemName').value.lastIndexOf('.');
    if (dotIndex > 0) {
      $('#createItemName').setSelectionRange(0, dotIndex);
    } else {
      $('#createItemName').select();
    }
  }
}

async function requestCreateItem(mode) {
  if (!vaultKey) {
    try {
      await waitForVaultUnlock();
    } catch (error) {
      if (error?.name !== 'AbortError') showToast(error.message || '无法解锁加密空间', 'error');
      return;
    }
  }
  openCreateItemModal(mode);
}

async function presentRemoteUpload(upload, index) {
  if (upload.encryption_version !== ENCRYPTION_VERSION || !vaultKey) {
    return {
      upload,
      name: upload.original_name && upload.original_name !== 'Encrypted file'
        ? upload.original_name : '加密上传任务',
      size: upload.plain_size ?? upload.size,
      locked: true
    };
  }
  try {
    const metadata = await decryptMetadata(upload);
    const presented = { upload, name: metadata.name, size: metadata.size, locked: false };
    metadata.fileKey = '';
    metadata.fileNonce = '';
    return presented;
  } catch {
    return { upload, name: '无法解密的文件', size: upload.plain_size ?? upload.size, locked: true };
  }
}

async function refreshRemoteUploads() {
  if (!me) return;
  let response = await api('/api/uploads');
  const now = Date.now();
  const recoveryCandidates = response.uploads.filter(upload => now - (remoteRecoveryAttemptAt.get(upload.id) || 0) >= 5000);
  if (recoveryCandidates.length) {
    const recovered = await Promise.all(recoveryCandidates.map(async upload => {
      remoteRecoveryAttemptAt.set(upload.id, now);
      try {
        await api('/api/uploads/' + upload.id + '/complete', { method: 'POST' });
        remoteRecoveryAttemptAt.delete(upload.id);
        return true;
      } catch (error) {
        if (error.status === 404 || error.status === 410) remoteRecoveryAttemptAt.delete(upload.id);
        return false;
      }
    }));
    if (recovered.some(Boolean)) {
      await loadFiles();
      response = await api('/api/uploads');
    }
  }
  const otherUploads = response.uploads.filter(upload => !uploads.has(upload.id));
  const displayUploads = await Promise.all(otherUploads.map(presentRemoteUpload));
  const section = $('#remoteUploads');
  section.hidden = displayUploads.length === 0;
  setTrustedHtml($('#remoteUploadList'), displayUploads.map(item => {
    const uploaded = Number(item.upload.uploaded_bytes) || 0;
    const total = item.upload.logical_size ?? item.upload.size;
    const ratio = total ? Math.min(100, uploaded / total * 100) : 100;
    const shownBytes = item.size * ratio / 100;
    const completed = uploaded >= total
      ? item.upload.chunk_count
      : Math.min(item.upload.chunk_count, Math.floor(uploaded / item.upload.chunk_size));
    const state = uploaded >= item.upload.size ? '等待另一页面确认保存' : '另一页面或先前会话保留的加密上传';
    return '<div class="upload-row remote-upload-row"><div class="file-info"><span class="file-name">' + escapeHtml(item.name) + '</span><span class="file-meta"><span>' + formatBytes(shownBytes) + ' / ' + formatBytes(item.size) + '</span><span class="upload-speed"> · ' + state + '</span></span><div class="progress-track"><div></div></div></div><div class="upload-actions"><span class="upload-percent">分片 ' + completed + ' / ' + item.upload.chunk_count + ' · ' + Math.floor(ratio) + '%</span><button type="button" class="cancel-upload remote-cancel-upload" data-id="' + item.upload.id + '">删除临时文件</button></div></div>';
  }).join(''));
  $('#remoteUploadList').querySelectorAll('.progress-track > div').forEach((bar, index) => {
    const upload = displayUploads[index]?.upload;
    const uploaded = Number(upload?.uploaded_bytes) || 0;
    bar.style.width = (upload?.size ? Math.min(100, uploaded / upload.size * 100) : 100) + '%';
  });
}

function stopRemoteUploadPolling() {
  if (remoteUploadTimer) clearInterval(remoteUploadTimer);
  remoteUploadTimer = null;
}

function startRemoteUploadPolling() {
  stopRemoteUploadPolling();
  remoteUploadTimer = setInterval(() => {
    refreshRemoteUploads().catch(() => {});
  }, 2000);
}

function setUploadState(task, text, danger = false) {
  const state = task.row.querySelector('.upload-percent');
  state.textContent = text;
  state.classList.toggle('danger', danger);
}

function updateUploadProgress(task) {
  const acknowledgedBytes = Array.from(task.chunkAcknowledgedProgress.values()).reduce((sum, bytes) => sum + bytes, 0);
  const sentBytes = Array.from(task.chunkProgress.values()).reduce((sum, bytes) => sum + bytes, 0);
  const transferredBytes = acknowledgedBytes >= task.file.size || task.file.size === 0
    ? task.file.size
    : Math.min(task.file.size - 1, Math.max(acknowledgedBytes, sentBytes));
  task.displayedBytes = Math.max(task.displayedBytes, Math.min(task.file.size, transferredBytes));
  const percent = task.file.size ? task.displayedBytes / task.file.size * 100 : 100;
  const speed = Array.from(task.chunkSpeeds.values()).reduce((sum, bytesPerSecond) => sum + bytesPerSecond, 0);
  task.row.querySelector('.progress-track div').style.width = percent + '%';
  task.row.querySelector('[data-upload-bytes]').textContent = formatBytes(task.displayedBytes) + ' / ' + formatBytes(task.file.size);
  task.row.querySelector('[data-upload-speed]').textContent = speed > 0 ? formatBytes(speed) + '/s' : '正在准备分片';
  if (!task.retrying && !task.saving) setUploadState(task, '分片 ' + Math.min(task.completedChunks, task.chunkCount || 0) + ' / ' + (task.chunkCount || 0) + ' · ' + Math.floor(percent) + '%');
}

function compressionSupported() {
  return typeof CompressionStream === 'function' && typeof DecompressionStream === 'function';
}

async function gzipChunk(bytes) {
  const stream = new Blob([bytes]).stream().pipeThrough(new CompressionStream(FILE_COMPRESSION_ALGORITHM));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function gunzipChunk(bytes) {
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream(FILE_COMPRESSION_ALGORITHM));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function encodeFileChunk(plaintext) {
  let mode = 0;
  let payload = new Uint8Array(plaintext);
  if (payload.byteLength > 0 && compressionSupported()) {
    const compressed = await gzipChunk(payload);
    if (compressed.byteLength < payload.byteLength) {
      mode = 1;
      payload = compressed;
    }
  }
  const framed = new Uint8Array(payload.byteLength + 1);
  framed[0] = mode;
  framed.set(payload, 1);
  return framed;
}

async function decodeFileChunk(value, metadata, expectedSize) {
  const bytes = new Uint8Array(value);
  if (metadata.version === ENCRYPTION_VERSION) {
    if (bytes.byteLength !== expectedSize) throw new Error('解密内容大小校验失败');
    return bytes;
  }
  if (bytes.byteLength < 1) throw new Error('压缩分片格式无效');
  const mode = bytes[0];
  const payload = bytes.subarray(1);
  const plaintext = mode === 0 ? payload : mode === 1 ? await gunzipChunk(payload) : null;
  if (!plaintext || plaintext.byteLength !== expectedSize) throw new Error('解压内容大小校验失败');
  return plaintext;
}

async function encryptChunk(task, index) {
  const start = index * task.plainChunkSize;
  const end = Math.min(task.file.size, start + task.plainChunkSize);
  const plaintext = await task.file.slice(start, end).arrayBuffer();
  const framed = await encodeFileChunk(plaintext);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: chunkIv(task.fileNonce, index), additionalData: chunkAad(task.id, index) },
    task.fileKey,
    framed
  );
  return { blob: new Blob([ciphertext], { type: 'application/octet-stream' }), plainSize: end - start };
}

function uploadChunk(task, index, encryptedChunk) {
  return new Promise((resolve, reject) => {
    if (task.controller.signal.aborted) return reject(abortError());
    const xhr = new XMLHttpRequest();
    const attemptStartedAt = performance.now();
    const onAbort = () => xhr.abort();
    const cleanup = () => {
      task.controller.signal.removeEventListener('abort', onAbort);
      task.currentXhrs.delete(xhr);
      task.chunkSpeeds.delete(index);
    };
    task.chunkProgress.set(index, 0);
    task.chunkAcknowledgedProgress.delete(index);
    task.chunkSpeeds.delete(index);
    task.currentXhrs.add(xhr);
    task.controller.signal.addEventListener('abort', onAbort, { once: true });
    xhr.open('PUT', '/api/uploads/' + task.id + '/chunks/' + index);
    xhr.setRequestHeader('Content-Type', 'application/octet-stream');
    xhr.upload.addEventListener('progress', event => {
      if (!event.lengthComputable) return;
      const elapsedSeconds = Math.max(.1, (performance.now() - attemptStartedAt) / 1000);
      const factor = encryptedChunk.plainSize / encryptedChunk.blob.size;
      task.chunkProgress.set(index, Math.min(encryptedChunk.plainSize, event.loaded * factor));
      task.chunkSpeeds.set(index, event.loaded * factor / elapsedSeconds);
      updateUploadProgress(task);
    });
    xhr.addEventListener('load', () => {
      cleanup();
      let data = {};
      try { data = JSON.parse(xhr.responseText || '{}'); } catch {}
      if (xhr.status >= 200 && xhr.status < 300) {
        task.chunkProgress.set(index, encryptedChunk.plainSize);
        task.chunkAcknowledgedProgress.set(index, encryptedChunk.plainSize);
        task.completedChunks += 1;
        updateUploadProgress(task);
        resolve(data);
      } else {
        task.chunkAcknowledgedProgress.delete(index);
        const error = new Error(data.error || '分片上传失败 (' + (xhr.status || '网络') + ')');
        error.status = xhr.status;
        error.retryable = (!data.error && xhr.status === 400)
          || [0, 408, 425, 429].includes(xhr.status)
          || xhr.status >= 500;
        reject(error);
      }
    });
    xhr.addEventListener('error', () => {
      cleanup();
      task.chunkAcknowledgedProgress.delete(index);
      updateUploadProgress(task);
      const error = new Error('网络连接中断');
      error.retryable = true;
      reject(error);
    });
    xhr.addEventListener('abort', () => {
      cleanup();
      task.chunkAcknowledgedProgress.delete(index);
      updateUploadProgress(task);
      reject(abortError());
    });
    xhr.send(encryptedChunk.blob);
  });
}

async function prepareEncryptedUpload(task) {
  if (!vaultKey) throw new Error('请先解锁端到端加密空间');
  const rawFileKey = randomBytes(32);
  task.fileKey = await crypto.subtle.importKey('raw', rawFileKey, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  task.fileNonce = randomBytes(8);
  task.plainChunkSize = PLAINTEXT_CHUNK_SIZE;
  task.chunkCount = Math.max(1, Math.ceil(task.file.size / task.plainChunkSize));
  task.plainChunkSizes = new Map();
  for (let index = 0; index < task.chunkCount; index += 1) {
    task.plainChunkSizes.set(index, Math.max(0, Math.min(task.plainChunkSize, task.file.size - index * task.plainChunkSize)));
  }
  const encryptedSizeUpperBound = task.file.size + task.chunkCount * (GCM_TAG_BYTES + 1);
  const metadata = await encryptMetadata(task.id, {
    version: FILE_FORMAT_VERSION,
    name: task.file.name,
    path: task.path,
    mime: task.file.type || 'application/octet-stream',
    size: task.file.size,
    plainChunkSize: task.plainChunkSize,
    compression: {
      version: FILE_COMPRESSION_VERSION,
      algorithm: FILE_COMPRESSION_ALGORITHM,
      framing: 'per-chunk'
    },
    fileKey: bytesToBase64url(rawFileKey),
    fileNonce: bytesToBase64url(task.fileNonce)
  });
  rawFileKey.fill(0);
  return { encryptedSizeUpperBound, encryption: { version: ENCRYPTION_VERSION, metadata: metadata.metadata, metadataIv: metadata.metadataIv } };
}

function updateUploadBatchControls() {
  const activeIds = [...uploads.values()].filter(task => !task.settled).map(task => task.id);
  const activeSet = new Set(activeIds);
  selectedUploadIds = new Set([...selectedUploadIds].filter(id => activeSet.has(id)));
  const selectAll = $('#selectAllUploads');
  if (selectAll) {
    selectAll.checked = activeIds.length > 0 && selectedUploadIds.size === activeIds.length;
    selectAll.indeterminate = selectedUploadIds.size > 0 && selectedUploadIds.size < activeIds.length;
    selectAll.disabled = activeIds.length === 0;
  }
  if ($('#cancelSelectedUploads')) $('#cancelSelectedUploads').disabled = selectedUploadIds.size === 0;
  if ($('#cancelAllUploads')) $('#cancelAllUploads').disabled = activeIds.length === 0;
  for (const task of uploads.values()) {
    const control = task.row.querySelector('.upload-select');
    if (control) control.setAttribute('aria-checked', String(selectedUploadIds.has(task.id)));
  }
}

function createUploadTask(entry) {
  const file = entry.file;
  const id = crypto.randomUUID();
  const row = document.createElement('div');
  row.className = 'upload-row local-upload-row';
  setTrustedHtml(row, '<button type="button" class="upload-select" role="checkbox" aria-checked="false" aria-label="选择此上传任务"></button><div class="file-info"><span class="file-name"></span><span class="file-meta"><span data-upload-bytes>0 B / ' + formatBytes(file.size) + '</span><span class="upload-speed"> · <span data-upload-speed>本地加密准备中</span></span></span><div class="progress-track"><div></div></div></div><div class="upload-actions"><span class="upload-percent">准备加密</span><button type="button" class="cancel-upload">取消上传</button></div>');
  row.querySelector('.file-name').textContent = entry.path ? entry.path + '/' + file.name : file.name;
  $('#uploadList').append(row);
  $('#uploads').hidden = false;
  const task = {
    id,
    file,
    path: entry.path,
    row,
    controller: new AbortController(),
    currentXhrs: new Set(),
    chunkProgress: new Map(),
    chunkAcknowledgedProgress: new Map(),
    chunkSpeeds: new Map(),
    plainChunkSizes: new Map(),
    cancelled: false,
    settled: false,
    cancelPromise: null,
    displayedBytes: 0,
    completedChunks: 0,
    retrying: false,
    saving: false
  };
  uploads.set(id, task);
  row.querySelector('.upload-select').addEventListener('click', () => {
    if (task.settled) return;
    if (selectedUploadIds.has(task.id)) selectedUploadIds.delete(task.id);
    else selectedUploadIds.add(task.id);
    updateUploadBatchControls();
  });
  row.querySelector('.cancel-upload').addEventListener('click', () => cancelUpload(task));
  updateUploadBatchControls();
  return task;
}

async function removeUploadTask(task, delay = 0) {
  if (delay) await wait(delay);
  uploads.delete(task.id);
  selectedUploadIds.delete(task.id);
  task.row.remove();
  $('#uploads').hidden = uploads.size === 0;
  updateUploadBatchControls();
}

async function deleteServerUpload(uploadId) {
  return withRetry(() => api('/api/uploads/' + uploadId, { method: 'DELETE' }), { attempts: 3 });
}

async function cancelUpload(task) {
  if (task.settled) return;
  if (task.cancelPromise) return task.cancelPromise;
  task.cancelled = true;
  selectedUploadIds.delete(task.id);
  updateUploadBatchControls();
  task.controller.abort();
  for (const xhr of task.currentXhrs) xhr.abort();
  task.row.querySelector('.cancel-upload').disabled = true;
  setUploadState(task, '取消中');
  task.cancelPromise = (async () => {
    try {
      await deleteServerUpload(task.id);
      setUploadState(task, '已取消');
      showToast(task.file.name + ' 已取消上传');
    } catch {
      setUploadState(task, '已停止');
      showToast(task.file.name + ' 已停止，服务器将自动清理临时分片');
    }
    task.row.classList.add('upload-cancelled');
    task.settled = true;
    updateUploadBatchControls();
    await removeUploadTask(task, 2200);
  })();
  return task.cancelPromise;
}

async function runUploadTask(task) {
  if (task.cancelled) return task.cancelPromise;
  try {
    setUploadState(task, '正在加密');
    const prepared = await prepareEncryptedUpload(task);
    if (task.cancelled) throw abortError();
    const upload = await retryWhileOnline(() => api('/api/uploads', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        id: task.id,
        size: prepared.encryptedSizeUpperBound,
        logicalSize: task.file.size,
        compressionVersion: FILE_COMPRESSION_VERSION,
        encryption: prepared.encryption,
        listingHint: {
          category: fileCategory(task.file.name, task.file.type),
          insideFolder: Boolean(task.path)
        }
      }),
      signal: task.controller.signal
    }), {
      signal: task.controller.signal,
      onRetry: (attempt, delay) => {
        task.retrying = true;
        setUploadState(task, '连接中断，重试 ' + attempt);
        task.row.querySelector('[data-upload-speed]').textContent = Math.ceil(delay / 1000) + ' 秒后继续';
      }
    });
    task.retrying = false;
    if (upload.chunkSize !== SERVER_CHUNK_SIZE || upload.chunkCount !== task.chunkCount) {
      const error = new Error('加密分片配置不匹配，请刷新后重试');
      error.retryable = false;
      throw error;
    }
    let nextChunkIndex = 0;
    const workerCount = Math.min(transferConcurrency(), upload.chunkCount);
    const uploadWorker = async workerIndex => {
      if (workerIndex > 0) await wait(UPLOAD_WORKER_STAGGER_MS * workerIndex, task.controller.signal);
      while (nextChunkIndex < upload.chunkCount) {
        const index = nextChunkIndex;
        nextChunkIndex += 1;
        const encryptedChunk = await encryptChunk(task, index);
        await retryWhileOnline(() => uploadChunk(task, index, encryptedChunk), {
          signal: task.controller.signal,
          onRetry: (attempt, delay) => {
            task.retrying = true;
            setUploadState(task, '分片重试 ' + attempt);
            task.row.querySelector('[data-upload-speed]').textContent = Math.ceil(delay / 1000) + ' 秒后继续';
          }
        });
        task.retrying = false;
      }
    };
    try {
      await Promise.all(Array.from({ length: workerCount }, (_, index) => uploadWorker(index)));
    } catch (error) {
      task.controller.abort();
      throw error;
    }
    task.saving = true;
    setUploadState(task, '正在保存');
    task.row.querySelector('[data-upload-speed]').textContent = '服务器正在合并加密分片';
    let completeAttempts = 0;
    await retryWhileOnline(() => api('/api/uploads/' + task.id + '/complete', { method: 'POST', signal: task.controller.signal }).catch(error => {
      completeAttempts += 1;
      if (error.status === 409 && /仍有加密分片未上传完成/.test(error.message || '') && completeAttempts < 6) {
        error.retryable = true;
      }
      throw error;
    }), {
      signal: task.controller.signal,
      onRetry: (attempt, delay) => {
        setUploadState(task, '保存确认重试 ' + attempt);
        task.row.querySelector('[data-upload-speed]').textContent = Math.ceil(delay / 1000) + ' 秒后继续';
      }
    });
    task.settled = true;
    updateUploadBatchControls();
    task.row.querySelector('.cancel-upload').disabled = true;
    setUploadState(task, '上传完成');
    me.used += task.file.size;
    updateStorage();
    await loadFiles();
    await refreshRemoteUploads();
    showToast(task.file.name + ' 已加密上传');
    await removeUploadTask(task, 900);
  } catch (error) {
    if (task.cancelled || isAbortError(error)) {
      if (!task.cancelPromise) await cancelUpload(task);
      else await task.cancelPromise;
      return;
    }
    setUploadState(task, '上传已暂停', true);
    task.row.querySelector('[data-upload-speed]').textContent = error.message;
    task.row.querySelector('.cancel-upload').disabled = false;
    showToast(task.file.name + ': ' + error.message + '，任务已保留');
  }
}

async function enqueueFiles(fileList) {
  const entries = Array.from(fileList || []).filter(entry => entry?.file instanceof File);
  if (!entries.length) return;
  if (!me?.encryption || !vaultKey) {
    pendingUploadFiles = entries;
    openVaultModal(me?.encryption ? 'unlock' : 'setup');
    showToast('请先解锁端到端加密空间');
    return;
  }
  const tasks = entries.map(createUploadTask);
  let nextTaskIndex = 0;
  const worker = async () => {
    while (nextTaskIndex < tasks.length) {
      const task = tasks[nextTaskIndex];
      nextTaskIndex += 1;
      if (!task.cancelled) await runUploadTask(task);
    }
  };
  await Promise.all(Array.from({ length: Math.min(FILE_UPLOAD_CONCURRENCY, tasks.length) }, worker));
}

async function resumePendingUploads() {
  const files = pendingUploadFiles;
  pendingUploadFiles = null;
  if (!files?.length || !vaultKey) return;
  await enqueueFiles(files);
}

function uploadEntriesFromFileList(fileList, basePath = currentDirectory) {
  return Array.from(fileList || []).map(file => {
    const relative = String(file.webkitRelativePath || '').replace(/\\/g, '/');
    const parts = relative.split('/').filter(Boolean);
    if (parts.length) parts.pop();
    return { file, path: joinFolderPath(basePath, parts.join('/')) };
  });
}

function fileFromEntry(entry) {
  return new Promise((resolve, reject) => entry.file(resolve, reject));
}

async function readDirectoryEntries(entry) {
  const reader = entry.createReader();
  const entries = [];
  while (true) {
    const batch = await new Promise((resolve, reject) => reader.readEntries(resolve, reject));
    if (!batch.length) return entries;
    entries.push(...batch);
  }
}

async function walkDroppedEntry(entry, relativeParent, basePath, output) {
  if (entry.isFile) {
    output.push({ file: await fileFromEntry(entry), path: joinFolderPath(basePath, relativeParent) });
    return;
  }
  if (!entry.isDirectory) return;
  const childParent = joinFolderPath(relativeParent, entry.name);
  for (const child of await readDirectoryEntries(entry)) {
    await walkDroppedEntry(child, childParent, basePath, output);
  }
}

async function uploadEntriesFromDrop(dataTransfer, basePath = currentDirectory) {
  const entries = [];
  const items = Array.from(dataTransfer?.items || []);
  const supportsFolders = items.some(item => typeof item.webkitGetAsEntry === 'function' && item.webkitGetAsEntry());
  if (!supportsFolders) return uploadEntriesFromFileList(dataTransfer?.files, basePath);
  for (const item of items) {
    const entry = item.webkitGetAsEntry?.();
    if (entry) await walkDroppedEntry(entry, '', basePath, entries);
  }
  return entries;
}

async function fetchEncryptedChunkWithProgress(fileId, index, signal, onProgress) {
  const cacheKey = fileId + ':' + index;
  const cached = previewChunkCache.get(cacheKey);
  if (cached) {
    previewChunkCache.delete(cacheKey);
    previewChunkCache.set(cacheKey, cached);
    onProgress?.(cached.byteLength);
    return cached.slice(0);
  }
  let request = previewChunkInflight.get(cacheKey);
  if (!request) {
    request = (async () => {
      const response = await fetch('/api/files/' + fileId + '/chunks/' + index, { signal, cache: 'no-store' });
      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        const error = new Error(data.error || '无法读取加密分片');
        error.retryable = [408, 425, 429].includes(response.status) || response.status >= 500;
        throw error;
      }
      if (!response.body) return response.arrayBuffer();
      const reader = response.body.getReader();
      const parts = [];
      let received = 0;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        parts.push(value);
        received += value.byteLength;
        onProgress?.(received);
      }
      const buffer = new Uint8Array(received);
      let offset = 0;
      for (const part of parts) {
        buffer.set(part, offset);
        offset += part.byteLength;
      }
      return buffer.buffer;
    })();
    previewChunkInflight.set(cacheKey, request);
  }
  let result;
  try {
    result = await request;
  } finally {
    if (previewChunkInflight.get(cacheKey) === request) previewChunkInflight.delete(cacheKey);
  }
  onProgress?.(result.byteLength);
  if (vaultKey && result.byteLength <= PREVIEW_CHUNK_CACHE_LIMIT) {
      const existing = previewChunkCache.get(cacheKey);
      if (existing) {
        previewChunkCache.delete(cacheKey);
        previewChunkCacheBytes -= existing.byteLength;
      }
      while (previewChunkCacheBytes + result.byteLength > PREVIEW_CHUNK_CACHE_LIMIT && previewChunkCache.size) {
        const [oldestKey, oldest] = previewChunkCache.entries().next().value;
        previewChunkCache.delete(oldestKey);
        previewChunkCacheBytes -= oldest.byteLength;
      }
      previewChunkCache.set(cacheKey, result.slice(0));
      previewChunkCacheBytes += result.byteLength;
    }
  return result;
}

function clearPreviewChunkCache() {
  previewPrefetchController?.abort();
  previewPrefetchController = null;
  previewChunkCache.clear();
  previewChunkInflight.clear();
  previewChunkCacheBytes = 0;
}

async function prefetchPreviewChunks(items) {
  if (!vaultKey) return;
  previewPrefetchController?.abort();
  const controller = new AbortController();
  previewPrefetchController = controller;
  const candidates = items.filter(item => item.encrypted && !item.locked
    && ['image', 'pdf', 'document', 'code'].includes(item.category)
    && item.size <= 8 * 1024 * 1024).slice(0, 3);
  for (const item of candidates) {
    if (controller.signal.aborted || !vaultKey) return;
    const chunkCount = item.file.chunk_count || 1;
    const queue = Array.from({ length: chunkCount }, (_, index) => index);
    let next = 0;
    const worker = async () => {
      while (next < queue.length && !controller.signal.aborted) {
        const index = queue[next++];
        await fetchEncryptedChunkWithProgress(item.file.id, index, controller.signal).catch(() => null);
      }
    };
    await Promise.all(Array.from({ length: Math.min(2, queue.length) }, worker));
  }
  if (previewPrefetchController === controller) previewPrefetchController = null;
}

async function requestClosePreviewModal() {
  if (previewEditorDirty) {
    const confirmed = await confirmAction({
      eyebrow: '未保存更改',
      title: '放弃未保存的更改？',
      message: '当前文档内容已被修改但尚未保存，如果直接关闭，未保存的修改将会丢失。',
      confirmLabel: '放弃更改并退出'
    });
    if (!confirmed) return;
  }
  closePreviewModal();
}

function closePreviewModal() {
  previewEditorDirty = false;
  previewEditorInitialContent = '';
  const modal = $('#previewModal');
  const stage = $('#previewStage');
  const controller = previewController;
  const cleanup = previewRendererCleanup;
  const objectUrl = previewObjectUrl;
  // Closing the UI must never wait for PDF.js cleanup. Some PDF render tasks
  // throw while being cancelled; hiding and clearing first keeps both close
  // controls reliable on desktop and mobile.
  if (modal) modal.hidden = true;
  if (stage) {
    stage.replaceChildren();
    stage.scrollTop = 0;
    stage.scrollLeft = 0;
  }
  previewController = null;
  previewRendererCleanup = null;
  previewObjectUrl = '';
  previewFileId = '';
  try { controller?.abort(); } catch {}
  try { cleanup?.(); } catch {}
  if (objectUrl) {
    try { URL.revokeObjectURL(objectUrl); } catch {}
  }
}

async function renderPdfPreview(blob, stage, signal) {
  const pdfjs = await import('/vendor/pdfjs/build/pdf.mjs');
  pdfjs.GlobalWorkerOptions.workerSrc = '/vendor/pdfjs/build/pdf.worker.mjs';
  if (signal.aborted) throw abortError();
  const loadingTask = pdfjs.getDocument({
    data: new Uint8Array(await blob.arrayBuffer()),
    isEvalSupported: false,
    useWasm: false,
    cMapUrl: '/vendor/pdfjs/cmaps/',
    cMapPacked: true,
    standardFontDataUrl: '/vendor/pdfjs/standard_fonts/'
  });
  let documentProxy = null;
  const renderTasks = new Set();
  const rendered = new Set();
  let disposed = false;
  previewRendererCleanup = () => {
    disposed = true;
    for (const task of renderTasks) {
      try { task.cancel(); } catch {}
    }
    renderTasks.clear();
    try {
      if (documentProxy) void documentProxy.destroy().catch(() => {});
      else void loadingTask.destroy().catch(() => {});
    } catch {}
  };
  documentProxy = await loadingTask.promise;
  if (signal.aborted || disposed) throw abortError();

  const viewer = document.createElement('div');
  viewer.className = 'pdf-preview';
  const summary = document.createElement('div');
  summary.className = 'pdf-preview-summary';
  summary.textContent = '共 ' + documentProxy.numPages + ' 页 · 在当前浏览器内安全渲染';
  viewer.append(summary);
  const pages = new Map();
  for (let pageNumber = 1; pageNumber <= documentProxy.numPages; pageNumber += 1) {
    const wrapper = document.createElement('section');
    wrapper.className = 'pdf-preview-page is-pending';
    wrapper.dataset.pageNumber = String(pageNumber);
    const label = document.createElement('span');
    label.className = 'pdf-preview-page-label';
    label.textContent = '第 ' + pageNumber + ' 页';
    wrapper.append(label);
    viewer.append(wrapper);
    pages.set(pageNumber, wrapper);
  }
  stage.replaceChildren(viewer);
  stage.scrollTop = 0;
  stage.scrollLeft = 0;

  const renderPage = async pageNumber => {
    if (disposed || signal.aborted || rendered.has(pageNumber)) return;
    rendered.add(pageNumber);
    const wrapper = pages.get(pageNumber);
    try {
      const page = await documentProxy.getPage(pageNumber);
      if (disposed || signal.aborted) return;
      const baseViewport = page.getViewport({ scale: 1 });
      wrapper.style.aspectRatio = baseViewport.width + ' / ' + baseViewport.height;
      const availableWidth = Math.max(280, Math.min(980, stage.clientWidth - 30));
      const cssScale = Math.max(.5, Math.min(1.75, availableWidth / baseViewport.width));
      const outputScale = Math.max(1, Math.min(2, window.devicePixelRatio || 1));
      const cssViewport = page.getViewport({ scale: cssScale });
      const viewport = page.getViewport({ scale: cssScale * outputScale });
      const canvas = document.createElement('canvas');
      canvas.width = Math.floor(viewport.width);
      canvas.height = Math.floor(viewport.height);
      canvas.style.width = Math.floor(cssViewport.width) + 'px';
      canvas.style.height = Math.floor(cssViewport.height) + 'px';
      canvas.setAttribute('aria-label', 'PDF 第 ' + pageNumber + ' 页');
      const task = page.render({ canvasContext: canvas.getContext('2d', { alpha: false }), viewport });
      renderTasks.add(task);
      await task.promise;
      renderTasks.delete(task);
      if (disposed || signal.aborted) return;
      wrapper.classList.remove('is-pending');
      wrapper.append(canvas);
      summary.textContent = '已渲染 ' + rendered.size + ' / ' + documentProxy.numPages + ' 页 · 当前浏览器安全预览';
      page.cleanup();
    } catch (error) {
      if (disposed || signal.aborted || error?.name === 'RenderingCancelledException') return;
      wrapper.classList.remove('is-pending');
      wrapper.classList.add('is-error');
      const message = document.createElement('strong');
      message.textContent = '第 ' + pageNumber + ' 页渲染失败';
      wrapper.append(message);
    }
  };

  await renderPage(1);
  if (documentProxy.numPages > 1 && !disposed && !signal.aborted) {
    // Render every remaining page in a small background pool. This avoids a
    // mobile IntersectionObserver edge case that left pages blank or partial,
    // while keeping the first page interactive immediately.
    let nextPage = 2;
    const worker = async () => {
      while (nextPage <= documentProxy.numPages && !disposed && !signal.aborted) {
        const pageNumber = nextPage;
        nextPage += 1;
        await renderPage(pageNumber);
      }
    };
    void Promise.all(Array.from({ length: Math.min(2, documentProxy.numPages - 1) }, worker)).catch(() => {});
  }
}

function previewMime(metadata) {
  const extension = metadata.name.split('.').pop()?.toLowerCase() || '';
  if (['mp3', 'wav', 'wave', 'aac', 'aav', 'm4a', 'flac', 'ogg', 'oga', 'opus'].includes(extension)) {
    return extension === 'mp3' ? 'audio/mpeg' : extension === 'flac' ? 'audio/flac' : extension === 'ogg' || extension === 'oga' ? 'audio/ogg' : extension === 'opus' ? 'audio/opus' : extension === 'wav' || extension === 'wave' ? 'audio/wav' : 'audio/aac';
  }
  if (['mp4', 'm4v', 'webm', 'mov', 'ogv', 'mkv', 'avi'].includes(extension)) {
    return extension === 'webm' ? 'video/webm' : extension === 'ogv' ? 'video/ogg' : 'video/mp4';
  }
  return metadata.mime || 'application/octet-stream';
}

function isTextPreview(metadata, mime) {
  const ext = metadata.name.split('.').pop()?.toLowerCase() || '';
  const baseName = metadata.name.toLowerCase();
  const knownExts = [
    'txt', 'text', 'log', 'ini', 'conf', 'config', 'env', 'properties',
    'md', 'markdown', 'mdown', 'json', 'jsonc', 'jsonl',
    'js', 'mjs', 'cjs', 'jsx', 'ts', 'mts', 'cts', 'tsx', 'vue', 'svelte',
    'html', 'htm', 'xhtml', 'css', 'scss', 'sass', 'less',
    'py', 'pyw', 'pyx', 'java', 'class', 'kt', 'kts', 'scala', 'sc', 'groovy',
    'c', 'h', 'cpp', 'cc', 'cxx', 'hpp', 'hxx', 'cs', 'go', 'rs', 'swift', 'dart',
    'php', 'phtml', 'rb', 'erb', 'lua', 'r', 'rmd', 'pl', 'pm',
    'sql', 'mysql', 'pgsql', 'sh', 'bash', 'zsh', 'ps1', 'psm1', 'bat', 'cmd',
    'xml', 'svg', 'xsl', 'xslt', 'yaml', 'yml', 'toml',
    'dockerfile', 'containerfile', 'makefile', 'mk',
    'tex', 'latex', 'graphql', 'gql', 'proto', 'diff', 'patch', 'csv', 'tsv'
  ];
  return mime.startsWith('text/') || knownExts.includes(ext) || ['dockerfile', 'makefile'].includes(baseName);
}

async function decryptFileToBlob(item, signal, onProgress) {
  const metadata = await decryptMetadata(item.file);
  if (metadata.size === 0) {
    const mime = previewMime(metadata);
    return { metadata, mime, blob: new Blob([], { type: mime }) };
  }
  if (metadata.size > 512 * 1024 * 1024) throw new Error('浏览器安全预览上限为 512 MB，请下载原文件后使用本机应用查看');
  const rawFileKey = base64urlToBytes(metadata.fileKey);
  metadata.fileKey = '';
  let fileKey;
  try {
    fileKey = await crypto.subtle.importKey('raw', rawFileKey, { name: 'AES-GCM' }, false, ['decrypt']);
  } finally {
    rawFileKey.fill(0);
  }
  const nonce = base64urlToBytes(metadata.fileNonce);
  metadata.fileNonce = '';
  const chunkCount = item.file.chunk_count || Math.max(1, Math.ceil(metadata.size / metadata.plainChunkSize));
  const pieces = new Array(chunkCount);
  let completed = 0;
  let nextChunk = 0;
  const worker = async () => {
    while (nextChunk < chunkCount) {
      if (signal.aborted) throw abortError();
      const index = nextChunk++;
      const ciphertext = await retryWhileOnline(() => fetchEncryptedChunkWithProgress(item.file.id, index, signal), { signal });
      const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: chunkIv(nonce, index), additionalData: chunkAad(item.file.upload_id, index) },
        fileKey,
        ciphertext
      );
      const expectedSize = Math.max(0, Math.min(metadata.plainChunkSize, metadata.size - index * metadata.plainChunkSize));
      pieces[index] = await decodeFileChunk(plaintext, metadata, expectedSize);
      completed += pieces[index].byteLength;
      onProgress?.(completed, metadata.size);
    }
  };
  await Promise.all(Array.from({ length: Math.min(PREVIEW_DOWNLOAD_CONCURRENCY, chunkCount) }, worker));
  if (completed !== metadata.size) throw new Error('预览内容大小校验失败');
  const mime = previewMime(metadata);
  return { metadata, mime, blob: new Blob(pieces, { type: mime }) };
}

async function openPreview(item) {
  if (!item || !vaultKey) {
    openVaultModal('unlock');
    return;
  }
  closePreviewModal();
  previewFileId = item.file.id;
  const controller = new AbortController();
  previewController = controller;
  $('#previewTitle').textContent = item.name;
  $('#previewStatus').textContent = '正在连接加密存储，并在当前浏览器中解密…';
  $('#previewModal').hidden = false;
  $('#previewStage').scrollTop = 0;
  $('#previewStage').scrollLeft = 0;
  const loading = document.createElement('div');
  loading.className = 'preview-loading';
  const spinner = document.createElement('span');
  spinner.className = 'preview-spinner';
  spinner.setAttribute('aria-hidden', 'true');
  const loadingTitle = document.createElement('strong');
  loadingTitle.textContent = '正在准备安全预览';
  const loadingCopy = document.createElement('span');
  loadingCopy.textContent = '加密分片正在并行读取，文件只会在本机解密。';
  loading.append(spinner, loadingTitle, loadingCopy);
  $('#previewStage').replaceChildren(loading);
  try {
    const result = await decryptFileToBlob(item, controller.signal, (completed, total) => {
      $('#previewStatus').textContent = '正在解密 ' + Math.floor((total ? completed / total : 1) * 100) + '% · 明文不会上传到服务器';
    });
    if (controller.signal.aborted || previewController !== controller || previewFileId !== item.file.id) return;
    const stage = $('#previewStage');
    let element;
    if (result.mime.startsWith('image/')) {
      previewObjectUrl = URL.createObjectURL(result.blob);
      element = document.createElement('img');
      element.alt = result.metadata.name;
      element.src = previewObjectUrl;
    } else if (result.mime.startsWith('audio/')) {
      previewObjectUrl = URL.createObjectURL(result.blob);
      element = document.createElement('audio');
      element.controls = true;
      element.preload = 'metadata';
      element.src = previewObjectUrl;
    } else if (result.mime.startsWith('video/')) {
      previewObjectUrl = URL.createObjectURL(result.blob);
      element = document.createElement('video');
      element.controls = true;
      element.preload = 'metadata';
      element.src = previewObjectUrl;
    } else if (result.mime === 'application/pdf') {
      await renderPdfPreview(result.blob, stage, controller.signal);
    } else if (isTextPreview(result.metadata, result.mime)) {
      const textContent = await result.blob.text();
      const ext = result.metadata.name.split('.').pop()?.toLowerCase() || '';
      const baseName = result.metadata.name.toLowerCase();

      // VS Code Grade Multi-Language Specs Registry
      const LANGUAGE_SPECS = {
        java: { name: 'Java', mode: 'code', comment: '// ' },
        c: { name: 'C', mode: 'code', comment: '// ' },
        cpp: { name: 'C++', mode: 'code', comment: '// ' },
        cc: { name: 'C++', mode: 'code', comment: '// ' },
        cxx: { name: 'C++', mode: 'code', comment: '// ' },
        h: { name: 'C/C++ Header', mode: 'code', comment: '// ' },
        hpp: { name: 'C++ Header', mode: 'code', comment: '// ' },
        cs: { name: 'C#', mode: 'code', comment: '// ' },
        go: { name: 'Go', mode: 'code', comment: '// ' },
        rs: { name: 'Rust', mode: 'code', comment: '// ' },
        py: { name: 'Python', mode: 'code', comment: '# ' },
        pyw: { name: 'Python', mode: 'code', comment: '# ' },
        js: { name: 'JavaScript', mode: 'code', comment: '// ' },
        mjs: { name: 'JavaScript (ESM)', mode: 'code', comment: '// ' },
        cjs: { name: 'JavaScript (CommonJS)', mode: 'code', comment: '// ' },
        ts: { name: 'TypeScript', mode: 'code', comment: '// ' },
        jsx: { name: 'JavaScript React (JSX)', mode: 'code', comment: '// ' },
        tsx: { name: 'TypeScript React (TSX)', mode: 'code', comment: '// ' },
        vue: { name: 'Vue', mode: 'code', comment: '<!-- ' },
        svelte: { name: 'Svelte', mode: 'code', comment: '<!-- ' },
        html: { name: 'HTML', mode: 'code', comment: '<!-- ' },
        htm: { name: 'HTML', mode: 'code', comment: '<!-- ' },
        css: { name: 'CSS', mode: 'code', comment: '/* ' },
        scss: { name: 'SCSS', mode: 'code', comment: '// ' },
        sass: { name: 'Sass', mode: 'code', comment: '// ' },
        less: { name: 'LESS', mode: 'code', comment: '// ' },
        php: { name: 'PHP', mode: 'code', comment: '// ' },
        rb: { name: 'Ruby', mode: 'code', comment: '# ' },
        kt: { name: 'Kotlin', mode: 'code', comment: '// ' },
        kts: { name: 'Kotlin Script', mode: 'code', comment: '// ' },
        swift: { name: 'Swift', mode: 'code', comment: '// ' },
        dart: { name: 'Dart', mode: 'code', comment: '// ' },
        scala: { name: 'Scala', mode: 'code', comment: '// ' },
        lua: { name: 'Lua', mode: 'code', comment: '-- ' },
        r: { name: 'R', mode: 'code', comment: '# ' },
        pl: { name: 'Perl', mode: 'code', comment: '# ' },
        sql: { name: 'SQL', mode: 'code', comment: '-- ' },
        sh: { name: 'Shell Script', mode: 'code', comment: '# ' },
        bash: { name: 'Bash', mode: 'code', comment: '# ' },
        zsh: { name: 'Zsh', mode: 'code', comment: '# ' },
        ps1: { name: 'PowerShell', mode: 'code', comment: '# ' },
        bat: { name: 'Batch', mode: 'code', comment: 'REM ' },
        cmd: { name: 'Batch (CMD)', mode: 'code', comment: 'REM ' },
        json: { name: 'JSON', mode: 'json', comment: '// ' },
        jsonc: { name: 'JSON with Comments', mode: 'json', comment: '// ' },
        jsonl: { name: 'JSON Lines', mode: 'json', comment: '// ' },
        xml: { name: 'XML', mode: 'code', comment: '<!-- ' },
        svg: { name: 'SVG XML', mode: 'code', comment: '<!-- ' },
        yaml: { name: 'YAML', mode: 'code', comment: '# ' },
        yml: { name: 'YAML', mode: 'code', comment: '# ' },
        toml: { name: 'TOML', mode: 'code', comment: '# ' },
        ini: { name: 'INI Config', mode: 'code', comment: '# ' },
        conf: { name: 'Config', mode: 'code', comment: '# ' },
        env: { name: 'Env Config', mode: 'code', comment: '# ' },
        properties: { name: 'Java Properties', mode: 'code', comment: '# ' },
        md: { name: 'Markdown', mode: 'markdown', comment: '<!-- ' },
        markdown: { name: 'Markdown', mode: 'markdown', comment: '<!-- ' },
        tex: { name: 'LaTeX', mode: 'code', comment: '% ' },
        graphql: { name: 'GraphQL', mode: 'code', comment: '# ' },
        proto: { name: 'Protocol Buffer', mode: 'code', comment: '// ' },
        dockerfile: { name: 'Dockerfile', mode: 'code', comment: '# ' },
        makefile: { name: 'Makefile', mode: 'code', comment: '# ' },
        csv: { name: 'CSV 表格', mode: 'txt', comment: '' },
        tsv: { name: 'TSV 表格', mode: 'txt', comment: '' },
        log: { name: 'Log 日志', mode: 'txt', comment: '' },
        txt: { name: '纯文本 (Plain Text)', mode: 'txt', comment: '' }
      };

      let currentLangKey = 'txt';
      if (baseName === 'dockerfile') currentLangKey = 'dockerfile';
      else if (baseName === 'makefile') currentLangKey = 'makefile';
      else if (LANGUAGE_SPECS[ext]) currentLangKey = ext;

      let currentLangSpec = LANGUAGE_SPECS[currentLangKey] || { name: '纯文本 (Plain Text)', mode: 'txt', comment: '' };

      let wordWrap = true;
      let showMarkdownPreview = false;

      const container = document.createElement('div');
      container.className = 'notepad-container';

      const menubar = document.createElement('div');
      menubar.className = 'notepad-menubar';

      const leftGroup = document.createElement('div');
      leftGroup.className = 'notepad-menu-group';

      const rightGroup = document.createElement('div');
      rightGroup.className = 'notepad-menu-group';

      function renderToolbar() {
        leftGroup.replaceChildren();
        const mode = currentLangSpec.mode;

        if (mode === 'markdown') {
          const headingDropdown = document.createElement('div');
          headingDropdown.className = 'notepad-dropdown';
          const headingBtn = document.createElement('button');
          headingBtn.type = 'button';
          headingBtn.className = 'notepad-btn';
          setTrustedHtml(headingBtn, '<strong>H1</strong> <span>标题样式 ▾</span>');

          const headingMenu = document.createElement('div');
          headingMenu.className = 'notepad-dropdown-menu';
          headingMenu.hidden = true;

          const headingOptions = [
            { label: 'Title (一级大标题)', prefix: '# ' },
            { label: 'Subtitle (二级副标题)', prefix: '## ' },
            { label: 'Heading (三级标题)', prefix: '### ' },
            { label: 'Subheading (四级标题)', prefix: '#### ' },
            { label: 'Section (五级段落节)', prefix: '##### ' },
            { label: 'Subsection (六级子节)', prefix: '###### ' },
            { label: 'Body (正文文本)', prefix: '' }
          ];

          headingOptions.forEach(opt => {
            const itemBtn = document.createElement('button');
            itemBtn.type = 'button';
            itemBtn.textContent = opt.label;
            itemBtn.addEventListener('click', () => {
              headingMenu.hidden = true;
              applyLinePrefix(opt.prefix);
            });
            headingMenu.append(itemBtn);
          });

          headingBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            headingMenu.hidden = !headingMenu.hidden;
          });
          headingDropdown.append(headingBtn, headingMenu);

          const boldBtn = document.createElement('button');
          boldBtn.type = 'button';
          boldBtn.className = 'notepad-btn is-bold';
          boldBtn.textContent = 'B';
          boldBtn.title = '粗体 (Ctrl+B)';
          boldBtn.addEventListener('click', () => wrapSelection('**', '**'));

          const italicBtn = document.createElement('button');
          italicBtn.type = 'button';
          italicBtn.className = 'notepad-btn is-italic';
          italicBtn.textContent = 'I';
          italicBtn.title = '斜体 (Ctrl+I)';
          italicBtn.addEventListener('click', () => wrapSelection('*', '*'));

          const strikeBtn = document.createElement('button');
          strikeBtn.type = 'button';
          strikeBtn.className = 'notepad-btn is-strike';
          strikeBtn.textContent = 'S';
          strikeBtn.title = '删除线';
          strikeBtn.addEventListener('click', () => wrapSelection('~~', '~~'));

          const codeBtn = document.createElement('button');
          codeBtn.type = 'button';
          codeBtn.className = 'notepad-btn';
          codeBtn.textContent = '</>';
          codeBtn.title = '代码块';
          codeBtn.addEventListener('click', () => wrapSelection('`', '`'));

          const listBtn = document.createElement('button');
          listBtn.type = 'button';
          listBtn.className = 'notepad-btn';
          listBtn.textContent = '• 列表';
          listBtn.addEventListener('click', () => applyLinePrefix('- '));

          const numListBtn = document.createElement('button');
          numListBtn.type = 'button';
          numListBtn.className = 'notepad-btn';
          numListBtn.textContent = '1. 序号';
          numListBtn.addEventListener('click', () => applyLinePrefix('1. '));

          const quoteBtn = document.createElement('button');
          quoteBtn.type = 'button';
          quoteBtn.className = 'notepad-btn';
          quoteBtn.textContent = '” 引用';
          quoteBtn.addEventListener('click', () => applyLinePrefix('> '));

          const linkBtn = document.createElement('button');
          linkBtn.type = 'button';
          linkBtn.className = 'notepad-btn';
          linkBtn.textContent = '🔗 链接';
          linkBtn.addEventListener('click', () => wrapSelection('[', '](url)'));

          leftGroup.append(headingDropdown, boldBtn, italicBtn, strikeBtn, codeBtn, listBtn, numListBtn, quoteBtn, linkBtn);
        } else if (mode === 'json') {
          const formatJsonBtn = document.createElement('button');
          formatJsonBtn.type = 'button';
          formatJsonBtn.className = 'notepad-btn notepad-btn-accent';
          formatJsonBtn.textContent = '✨ 格式化 JSON';
          formatJsonBtn.title = '美化并排版 JSON 结构';
          formatJsonBtn.addEventListener('click', () => {
            try {
              const parsed = JSON.parse(textarea.value);
              textarea.value = JSON.stringify(parsed, null, 2);
              updateStatsAndPos();
              showToast('JSON 格式化成功');
            } catch (e) {
              showToast('JSON 语法错误: ' + e.message);
            }
          });

          const timeBtn = document.createElement('button');
          timeBtn.type = 'button';
          timeBtn.className = 'notepad-btn';
          timeBtn.textContent = '⏱️ 插入时间 (F5)';
          timeBtn.addEventListener('click', () => insertTextAtCursor(new Date().toISOString()));

          leftGroup.append(formatJsonBtn, timeBtn);
        } else if (mode === 'code') {
          const commentBtn = document.createElement('button');
          commentBtn.type = 'button';
          commentBtn.className = 'notepad-btn';
          commentBtn.textContent = '// 切换注释 (Ctrl+/)';
          commentBtn.title = '切换注释行';
          commentBtn.addEventListener('click', () => {
            const commentStr = currentLangSpec.comment || '// ';
            applyLinePrefix(commentStr);
          });

          const indentBtn = document.createElement('button');
          indentBtn.type = 'button';
          indentBtn.className = 'notepad-btn';
          indentBtn.textContent = '⇥ 缩进 4 空格 (Tab)';
          indentBtn.addEventListener('click', () => insertTextAtCursor('    '));

          const timeBtn = document.createElement('button');
          timeBtn.type = 'button';
          timeBtn.className = 'notepad-btn';
          timeBtn.textContent = '⏱️ 插入时间 (F5)';
          timeBtn.addEventListener('click', () => insertTextAtCursor(new Date().toLocaleString()));

          leftGroup.append(commentBtn, indentBtn, timeBtn);
        } else {
          const timeBtn = document.createElement('button');
          timeBtn.type = 'button';
          timeBtn.className = 'notepad-btn';
          timeBtn.textContent = '⏱️ 插入时间 (F5)';
          timeBtn.title = '插入系统时间日期';
          timeBtn.addEventListener('click', () => insertTextAtCursor(new Date().toLocaleString()));

          leftGroup.append(timeBtn);
        }
      }

      renderToolbar();

      const previewToggleBtn = document.createElement('button');
      previewToggleBtn.type = 'button';
      previewToggleBtn.className = 'notepad-btn';
      previewToggleBtn.textContent = '👁️ 实时预览: 关';
      previewToggleBtn.title = '开启/关闭 Markdown 分栏渲染预览';
      previewToggleBtn.addEventListener('click', () => {
        showMarkdownPreview = !showMarkdownPreview;
        previewToggleBtn.textContent = showMarkdownPreview ? '👁️ 实时预览: 开' : '👁️ 实时预览: 关';
        previewToggleBtn.classList.toggle('is-active', showMarkdownPreview);
        previewPane.hidden = !showMarkdownPreview;
        if (showMarkdownPreview) renderMarkdownPreview();
      });

      const findBtn = document.createElement('button');
      findBtn.type = 'button';
      findBtn.className = 'notepad-btn';
      findBtn.textContent = '🔍 查找与替换';
      findBtn.title = '查找与替换 (Ctrl+F)';

      const wrapBtn = document.createElement('button');
      wrapBtn.type = 'button';
      wrapBtn.className = 'notepad-btn is-active';
      wrapBtn.textContent = '自动换行: 开';
      wrapBtn.addEventListener('click', () => {
        wordWrap = !wordWrap;
        wrapBtn.textContent = wordWrap ? '自动换行: 开' : '自动换行: 关';
        wrapBtn.classList.toggle('is-active', wordWrap);
        textarea.className = 'notepad-textarea ' + (wordWrap ? 'word-wrap' : 'no-wrap');
      });

      if (currentLangSpec.mode === 'markdown') rightGroup.append(previewToggleBtn);
      rightGroup.append(findBtn, wrapBtn);
      menubar.append(leftGroup, rightGroup);

      const findBar = document.createElement('div');
      findBar.className = 'notepad-find-bar';
      findBar.hidden = true;

      const findInput = document.createElement('input');
      findInput.type = 'text';
      findInput.className = 'notepad-find-input';
      findInput.placeholder = '查找内容…';

      const replaceInput = document.createElement('input');
      replaceInput.type = 'text';
      replaceInput.className = 'notepad-find-input';
      replaceInput.placeholder = '替换为…';

      const findNextBtn = document.createElement('button');
      findNextBtn.type = 'button';
      findNextBtn.className = 'notepad-btn';
      findNextBtn.textContent = '查找下一个';

      const replaceBtn = document.createElement('button');
      replaceBtn.type = 'button';
      replaceBtn.className = 'notepad-btn';
      replaceBtn.textContent = '替换';

      const replaceAllBtn = document.createElement('button');
      replaceAllBtn.type = 'button';
      replaceAllBtn.className = 'notepad-btn';
      replaceAllBtn.textContent = '全部替换';

      const closeFindBtn = document.createElement('button');
      closeFindBtn.type = 'button';
      closeFindBtn.className = 'notepad-btn';
      closeFindBtn.textContent = '✕';

      const findCount = document.createElement('span');
      findCount.className = 'notepad-find-count';

      findBar.append(findInput, replaceInput, findNextBtn, replaceBtn, replaceAllBtn, findCount, closeFindBtn);

      findBtn.addEventListener('click', () => {
        findBar.hidden = !findBar.hidden;
        if (!findBar.hidden) {
          findInput.focus();
          findInput.select();
        }
      });
      closeFindBtn.addEventListener('click', () => { findBar.hidden = true; textarea.focus(); });

      const bodyWrapper = document.createElement('div');
      bodyWrapper.className = 'notepad-body';

      const editorCore = document.createElement('div');
      editorCore.className = 'notepad-editor-core';

      const gutter = document.createElement('div');
      gutter.className = 'notepad-gutter';

      const textareaWrap = document.createElement('div');
      textareaWrap.className = 'notepad-textarea-wrap';

      const textarea = document.createElement('textarea');
      textarea.className = 'notepad-textarea word-wrap';
      textarea.value = textContent;
      textarea.spellcheck = false;
      textarea.placeholder = '在此输入代码或文本内容…';

      textareaWrap.append(textarea);
      editorCore.append(gutter, textareaWrap);

      const previewPane = document.createElement('div');
      previewPane.className = 'notepad-preview-pane';
      previewPane.hidden = true;

      bodyWrapper.append(editorCore, previewPane);

      function renderMarkdownPreview() {
        if (!showMarkdownPreview) return;
        const md = textarea.value;
        let html = '';
        const lines = md.split('\n');
        let inCodeBlock = false;
        let inList = false;

        for (let i = 0; i < lines.length; i++) {
          let line = lines[i];
          if (line.startsWith('```')) {
            if (inCodeBlock) { html += '</code></pre>'; inCodeBlock = false; }
            else { html += '<pre><code>'; inCodeBlock = true; }
            continue;
          }
          if (inCodeBlock) {
            html += escapeHtml(line) + '\n';
            continue;
          }
          if (line.startsWith('# ')) {
            html += '<h1>' + escapeHtml(line.slice(2)) + '</h1>';
          } else if (line.startsWith('## ')) {
            html += '<h2>' + escapeHtml(line.slice(3)) + '</h2>';
          } else if (line.startsWith('### ')) {
            html += '<h3>' + escapeHtml(line.slice(4)) + '</h3>';
          } else if (line.startsWith('#### ')) {
            html += '<h4>' + escapeHtml(line.slice(5)) + '</h4>';
          } else if (line.startsWith('##### ')) {
            html += '<h5>' + escapeHtml(line.slice(6)) + '</h5>';
          } else if (line.startsWith('###### ')) {
            html += '<h6>' + escapeHtml(line.slice(7)) + '</h6>';
          } else if (line.startsWith('> ')) {
            html += '<blockquote>' + escapeHtml(line.slice(2)) + '</blockquote>';
          } else if (line.startsWith('- ') || line.startsWith('* ')) {
            if (!inList) { html += '<ul>'; inList = true; }
            html += '<li>' + escapeHtml(line.slice(2)) + '</li>';
          } else if (line.trim() === '') {
            if (inList) { html += '</ul>'; inList = false; }
            html += '<br>';
          } else {
            if (inList) { html += '</ul>'; inList = false; }
            let formatted = escapeHtml(line);
            formatted = formatted.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
            formatted = formatted.replace(/\*(.*?)\*/g, '<em>$1</em>');
            formatted = formatted.replace(/~~(.*?)~~/g, '<del>$1</del>');
            formatted = formatted.replace(/`([^`]+)`/g, '<code>$1</code>');
            formatted = formatted.replace(/\[([^\]]+)\]\(([^\)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
            html += '<p>' + formatted + '</p>';
          }
        }
        if (inCodeBlock) html += '</code></pre>';
        if (inList) html += '</ul>';
        setTrustedHtml(previewPane, html);
      }

      const statusbar = document.createElement('div');
      statusbar.className = 'notepad-statusbar';

      const statusLeft = document.createElement('div');
      statusLeft.className = 'notepad-status-left';

      const posSpan = document.createElement('span');
      posSpan.className = 'notepad-status-item';
      posSpan.textContent = 'Ln 1, Col 1';

      const charSpan = document.createElement('span');
      charSpan.className = 'notepad-status-item';

      const indentSpan = document.createElement('span');
      indentSpan.className = 'notepad-status-item';
      indentSpan.textContent = 'Spaces: 4';

      const crlfSpan = document.createElement('span');
      crlfSpan.className = 'notepad-status-item';
      crlfSpan.textContent = textContent.includes('\r\n') ? 'CRLF' : 'LF';

      const encodingSpan = document.createElement('span');
      encodingSpan.className = 'notepad-status-item';
      encodingSpan.textContent = 'UTF-8';

      const div1 = document.createElement('span'); div1.className = 'notepad-status-divider'; div1.textContent = '|';
      const div2 = document.createElement('span'); div2.className = 'notepad-status-divider'; div2.textContent = '|';
      const div3 = document.createElement('span'); div3.className = 'notepad-status-divider'; div3.textContent = '|';
      const div4 = document.createElement('span'); div4.className = 'notepad-status-divider'; div4.textContent = '|';

      statusLeft.append(posSpan, div1, charSpan, div2, indentSpan, div3, crlfSpan, div4, encodingSpan);

      const statusRight = document.createElement('div');
      statusRight.className = 'notepad-status-right';

      const langBtn = document.createElement('button');
      langBtn.type = 'button';
      langBtn.className = 'notepad-lang-switcher-btn';
      langBtn.textContent = `${currentLangSpec.name} ▾`;
      langBtn.title = '点击切换语言模式 (VS Code Language Mode)';

      const langPopup = document.createElement('div');
      langPopup.className = 'notepad-lang-popup';
      langPopup.hidden = true;

      const uniqueLanguages = [
        { key: 'java', name: 'Java' },
        { key: 'py', name: 'Python' },
        { key: 'c', name: 'C' },
        { key: 'cpp', name: 'C++' },
        { key: 'cs', name: 'C#' },
        { key: 'go', name: 'Go' },
        { key: 'rs', name: 'Rust' },
        { key: 'js', name: 'JavaScript' },
        { key: 'ts', name: 'TypeScript' },
        { key: 'html', name: 'HTML' },
        { key: 'css', name: 'CSS' },
        { key: 'sql', name: 'SQL' },
        { key: 'sh', name: 'Shell (Bash)' },
        { key: 'ps1', name: 'PowerShell' },
        { key: 'json', name: 'JSON' },
        { key: 'yaml', name: 'YAML' },
        { key: 'xml', name: 'XML' },
        { key: 'toml', name: 'TOML' },
        { key: 'md', name: 'Markdown' },
        { key: 'php', name: 'PHP' },
        { key: 'rb', name: 'Ruby' },
        { key: 'kt', name: 'Kotlin' },
        { key: 'swift', name: 'Swift' },
        { key: 'dart', name: 'Dart' },
        { key: 'scala', name: 'Scala' },
        { key: 'lua', name: 'Lua' },
        { key: 'r', name: 'R' },
        { key: 'dockerfile', name: 'Dockerfile' },
        { key: 'makefile', name: 'Makefile' },
        { key: 'txt', name: '纯文本 (Plain Text)' }
      ];

      uniqueLanguages.forEach(lang => {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.textContent = lang.name;
        if (lang.key === currentLangKey) btn.className = 'active';
        btn.addEventListener('click', () => {
          currentLangKey = lang.key;
          currentLangSpec = LANGUAGE_SPECS[lang.key] || { name: lang.name, mode: 'code', comment: '// ' };
          langBtn.textContent = `${currentLangSpec.name} ▾`;
          langPopup.hidden = true;
          renderToolbar();
          if (currentLangSpec.mode === 'markdown') {
            if (!rightGroup.contains(previewToggleBtn)) rightGroup.prepend(previewToggleBtn);
          } else {
            previewToggleBtn.remove();
            previewPane.hidden = true;
            showMarkdownPreview = false;
          }
          showToast(`已切换语言模式为: ${currentLangSpec.name}`);
        });
        langPopup.append(btn);
      });

      langBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        langPopup.hidden = !langPopup.hidden;
      });

      document.addEventListener('click', (e) => {
        if (!langPopup.contains(e.target) && e.target !== langBtn) langPopup.hidden = true;
      });

      const dirtyBadge = document.createElement('span');
      dirtyBadge.className = 'notepad-dirty-badge';
      dirtyBadge.hidden = true;
      dirtyBadge.textContent = '● 未保存';

      const saveBtn = document.createElement('button');
      saveBtn.type = 'button';
      saveBtn.className = 'primary notepad-save-btn';
      saveBtn.textContent = '保存修改 (Ctrl+S)';

      statusRight.append(langBtn, langPopup, dirtyBadge, saveBtn);
      statusbar.append(statusLeft, statusRight);

      function updateGutter(currentLineNum, totalLines) {
        let gutterHtml = '';
        for (let i = 1; i <= totalLines; i++) {
          const isCur = (i === currentLineNum);
          gutterHtml += `<div class="notepad-gutter-line${isCur ? ' current-line' : ''}">${i}</div>`;
        }
        setTrustedHtml(gutter, gutterHtml);
      }

      textarea.addEventListener('scroll', () => {
        gutter.scrollTop = textarea.scrollTop;
      });

      previewEditorInitialContent = textContent;
      previewEditorDirty = false;

      function updateStatsAndPos() {
        const pos = textarea.selectionStart;
        const end = textarea.selectionEnd;
        const val = textarea.value;
        const linesBefore = val.slice(0, pos).split('\n');
        const lineNum = linesBefore.length;
        const colNum = linesBefore[linesBefore.length - 1].length + 1;
        posSpan.textContent = `Ln ${lineNum}, Col ${colNum}`;

        const totalChars = val.length;
        const totalLines = Math.max(1, val.split('\n').length);
        if (end > pos) {
          charSpan.textContent = `${end - pos} 字符已选择 (共 ${totalChars} 字符 · ${totalLines} 行)`;
        } else {
          charSpan.textContent = `${totalChars} 字符 · ${totalLines} 行`;
        }

        updateGutter(lineNum, totalLines);

        previewEditorDirty = (val !== previewEditorInitialContent);
        dirtyBadge.hidden = !previewEditorDirty;

        if (showMarkdownPreview) renderMarkdownPreview();
      }

      textarea.addEventListener('input', updateStatsAndPos);
      textarea.addEventListener('click', updateStatsAndPos);
      textarea.addEventListener('keyup', updateStatsAndPos);
      textarea.addEventListener('select', updateStatsAndPos);
      updateStatsAndPos();

      function insertTextAtCursor(text) {
        const start = textarea.selectionStart;
        const end = textarea.selectionEnd;
        textarea.setRangeText(text, start, end, 'end');
        updateStatsAndPos();
        textarea.focus();
      }

      function wrapSelection(before, after) {
        const start = textarea.selectionStart;
        const end = textarea.selectionEnd;
        const selected = textarea.value.slice(start, end);
        const replacement = before + (selected || '文本') + after;
        textarea.setRangeText(replacement, start, end, 'select');
        if (!selected) {
          textarea.setSelectionRange(start + before.length, start + before.length + 2);
        }
        updateStatsAndPos();
        textarea.focus();
      }

      function applyLinePrefix(prefix) {
        const start = textarea.selectionStart;
        const val = textarea.value;
        const lineStart = val.lastIndexOf('\n', start - 1) + 1;
        let lineEnd = val.indexOf('\n', start);
        if (lineEnd === -1) lineEnd = val.length;
        const currentLine = val.slice(lineStart, lineEnd);
        const cleanedLine = currentLine.replace(/^(?:#{1,6}\s*|- |\d+\.\s*|>\s*|\/\/\s*|#\s*|--\s*|REM\s*|<!--\s*)/, '');
        const newLine = prefix + cleanedLine;
        textarea.setRangeText(newLine, lineStart, lineEnd, 'end');
        updateStatsAndPos();
        textarea.focus();
      }

      function performFind(next = true) {
        const query = findInput.value;
        if (!query) { findCount.textContent = ''; return; }
        const text = textarea.value;
        const matches = [...text.matchAll(new RegExp(query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'))];
        findCount.textContent = matches.length ? `${matches.length} 处匹配` : '无匹配';
        if (!matches.length) return;
        const caret = textarea.selectionEnd;
        let target = matches.find(m => m.index >= caret);
        if (!target) target = matches[0];
        textarea.setSelectionRange(target.index, target.index + query.length);
        textarea.focus();
      }

      findNextBtn.addEventListener('click', () => performFind(true));
      findInput.addEventListener('keydown', e => { if (e.key === 'Enter') performFind(true); });

      replaceBtn.addEventListener('click', () => {
        const query = findInput.value;
        if (!query) return;
        const start = textarea.selectionStart;
        const end = textarea.selectionEnd;
        if (textarea.value.slice(start, end).toLowerCase() === query.toLowerCase()) {
          textarea.setRangeText(replaceInput.value, start, end, 'end');
          updateStatsAndPos();
        }
        performFind(true);
      });

      replaceAllBtn.addEventListener('click', () => {
        const query = findInput.value;
        if (!query) return;
        const regex = new RegExp(query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g');
        textarea.value = textarea.value.replace(regex, replaceInput.value);
        updateStatsAndPos();
        findCount.textContent = '已全部替换';
      });

      textarea.addEventListener('keydown', event => {
        if (event.key === 'Tab') {
          event.preventDefault();
          const start = textarea.selectionStart;
          const end = textarea.selectionEnd;
          textarea.setRangeText('    ', start, end, 'end');
          updateStatsAndPos();
        } else if (event.key === 'F5') {
          event.preventDefault();
          insertTextAtCursor(new Date().toLocaleString());
        } else if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 's') {
          event.preventDefault();
          saveAction();
        } else if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'f') {
          event.preventDefault();
          findBar.hidden = false;
          findInput.focus();
          findInput.select();
        } else if ((event.ctrlKey || event.metaKey) && event.key === '/') {
          event.preventDefault();
          const commentStr = currentLangSpec.comment || '// ';
          applyLinePrefix(commentStr);
        } else if (currentLangSpec.mode === 'markdown') {
          if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'b') {
            event.preventDefault();
            wrapSelection('**', '**');
          } else if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'i') {
            event.preventDefault();
            wrapSelection('*', '*');
          }
        }
      });

      const saveAction = async () => {
        if (saveBtn.disabled) return;
        saveBtn.disabled = true;
        saveBtn.textContent = '正在加密保存…';
        try {
          const newText = textarea.value;
          const textBytes = new TextEncoder().encode(newText);
          const uploadId = crypto.randomUUID();
          const rawFileKey = randomBytes(32);
          const fileNonce = randomBytes(8);
          const newSize = textBytes.length;

          let chunkCount = 0;
          let encryptedChunkBase64 = '';
          let encryptedSize = 0;

          if (newSize > 0) {
            const importedKey = await crypto.subtle.importKey('raw', rawFileKey, { name: 'AES-GCM' }, false, ['encrypt']);
            const ciphertext = await crypto.subtle.encrypt(
              { name: 'AES-GCM', iv: chunkIv(fileNonce, 0), additionalData: chunkAad(uploadId, 0) },
              importedKey,
              textBytes
            );
            encryptedChunkBase64 = bytesToBase64url(new Uint8Array(ciphertext));
            encryptedChunkBase64 = encryptedChunkBase64.replace(/-/g, '+').replace(/_/g, '/');
            while (encryptedChunkBase64.length % 4) encryptedChunkBase64 += '=';
            chunkCount = 1;
            encryptedSize = ciphertext.byteLength;
          }

          const newMetadata = {
            version: ENCRYPTION_VERSION,
            name: result.metadata.name,
            path: result.metadata.path || currentDirectory,
            mime: result.mime,
            size: newSize,
            plainChunkSize: LEGACY_PLAINTEXT_CHUNK_SIZE,
            fileKey: bytesToBase64url(rawFileKey),
            fileNonce: bytesToBase64url(fileNonce)
          };
          const encResult = await encryptMetadata(uploadId, newMetadata);
          rawFileKey.fill(0);

          await api(`/api/files/${encodeURIComponent(item.file.id)}/content`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              uploadId,
              size: encryptedSize,
              chunkCount,
              encryptedChunk: encryptedChunkBase64,
              category: listingCategory(fileCategory(result.metadata.name, result.mime)),
              insideFolder: Boolean(result.metadata.path),
              encryption: { version: ENCRYPTION_VERSION, ...encResult }
            })
          });

          previewEditorInitialContent = newText;
          previewEditorDirty = false;
          updateStatsAndPos();

          item.file.upload_id = uploadId;
          item.file.size = encryptedSize;
          item.file.chunk_count = chunkCount;
          item.file.encrypted_metadata = encResult.metadata;
          item.file.encrypted_metadata_iv = encResult.metadataIv;
          item.size = newSize;
          result.metadata.size = newSize;

          clearPreviewChunkCache();
          await loadFiles();
          showToast('文件已成功保存并端到端加密');
          saveBtn.textContent = '已保存 ✓';
          setTimeout(() => { saveBtn.textContent = '保存修改 (Ctrl+S)'; }, 2000);
        } catch (err) {
          console.error('Save text file error:', err);
          showToast('保存失败: ' + (err.message || '请稍后重试'));
          saveBtn.textContent = '保存失败，点击重试';
        } finally {
          saveBtn.disabled = false;
        }
      };

      saveBtn.addEventListener('click', saveAction);

      container.append(menubar, findBar, bodyWrapper, statusbar);
      element = container;
    } else {
      element = document.createElement('div');
      element.className = 'preview-fallback';
      const title = document.createElement('strong');
      title.textContent = '此格式已安全解密，但浏览器没有可用的内置解码器';
      const copy = document.createElement('span');
      copy.textContent = result.metadata.name + ' · ' + formatBytes(result.metadata.size) + ' · ' + result.mime + '。你仍可下载原文件并使用本机应用打开。';
      element.append(title, copy);
    }
    if (element) stage.replaceChildren(element);
    $('#previewStatus').textContent = '预览仅存在于当前浏览器内存；关闭后立即释放';
  } catch (error) {
    if (isAbortError(error) || controller.signal.aborted || previewController !== controller) return;
    const fallback = document.createElement('div');
    fallback.className = 'preview-fallback';
    const title = document.createElement('strong');
    title.textContent = '无法预览此文件';
    const copy = document.createElement('span');
    copy.textContent = error.message || '预览失败';
    fallback.append(title, copy);
    $('#previewStage').replaceChildren(fallback);
    $('#previewStatus').textContent = '预览失败';
  }
}

function setDownloadState(task, text, danger = false) {
  const state = task.row.querySelector('.upload-percent');
  state.textContent = text;
  state.classList.toggle('danger', danger);
}

function updateDownloadProgress(task) {
  const total = task.metadata.size;
  const currentBytes = Math.min(total, task.completedBytes + task.partialBytes);
  task.displayedBytes = Math.max(task.displayedBytes, currentBytes);
  const percent = total ? task.displayedBytes / total * 100 : 100;
  const elapsedSeconds = Math.max(.1, (performance.now() - task.startedAt) / 1000);
  const speed = task.displayedBytes / elapsedSeconds;
  task.row.querySelector('.progress-track div').style.width = percent + '%';
  task.row.querySelector('[data-download-bytes]').textContent = formatBytes(task.displayedBytes) + ' / ' + formatBytes(total);
  task.row.querySelector('[data-download-speed]').textContent = speed > 0 ? formatBytes(speed) + '/s' : '正在准备下载';
  if (!task.retrying && !task.writing) {
    setDownloadState(task, '分片 ' + Math.min(task.completedChunks, task.chunkCount) + ' / ' + task.chunkCount + ' · ' + Math.floor(percent) + '%');
  }
}

function createDownloadTask(item) {
  const metadata = item.metadata;
  const chunkSize = item.file.chunk_size || SERVER_CHUNK_SIZE;
  const chunkCount = item.file.chunk_count || Math.max(1, Math.ceil(item.file.size / chunkSize));
  const row = document.createElement('div');
  row.className = 'upload-row download-row';
  setTrustedHtml(row, '<div class="file-info"><span class="file-name"></span><span class="file-meta"><span data-download-bytes>0 B / ' + formatBytes(metadata.size) + '</span><span class="upload-speed"> · <span data-download-speed>等待开始</span></span></span><div class="progress-track"><div></div></div></div><div class="upload-actions"><span class="upload-percent">选择保存位置</span><button type="button" class="cancel-upload cancel-download">取消下载</button></div>');
  row.querySelector('.file-name').textContent = metadata.name;
  $('#downloadList').append(row);
  $('#downloads').hidden = false;
  const task = {
    id: item.file.id,
    item,
    metadata,
    chunkSize,
    chunkCount,
    row,
    controller: new AbortController(),
    cancelled: false,
    settled: false,
    cancelPromise: null,
    writable: null,
    completedBytes: 0,
    partialBytes: 0,
    displayedBytes: 0,
    completedChunks: 0,
    retrying: false,
    writing: false,
    startedAt: performance.now()
  };
  downloads.set(task.id, task);
  row.querySelector('.cancel-download').addEventListener('click', () => cancelDownload(task));
  return task;
}

async function removeDownloadTask(task, delay = 0) {
  if (delay) await wait(delay);
  downloads.delete(task.id);
  task.row.remove();
  $('#downloads').hidden = downloads.size === 0;
}

async function cancelDownload(task) {
  if (task.settled) return;
  if (task.cancelPromise) return task.cancelPromise;
  task.cancelled = true;
  task.controller.abort();
  task.row.querySelector('.cancel-download').disabled = true;
  setDownloadState(task, '取消中');
  task.cancelPromise = (async () => {
    try {
      await task.writable?.abort?.();
    } catch {
      // The stream may already be closed or aborted.
    }
    task.row.classList.add('upload-cancelled');
    task.settled = true;
    setDownloadState(task, '已取消');
    task.row.querySelector('[data-download-speed]').textContent = '未保存到设备';
    showToast(task.metadata.name + ' 已取消下载');
    await removeDownloadTask(task, 2200);
  })();
  return task.cancelPromise;
}

function numberedDownloadName(name, sequence) {
  const dot = name.lastIndexOf('.');
  if (dot <= 0) return name + ' (' + sequence + ')';
  return name.slice(0, dot) + ' (' + sequence + ')' + name.slice(dot);
}

async function availableDownloadFileHandle(directory, name) {
  for (let sequence = 0; sequence < 1000; sequence += 1) {
    const candidate = sequence ? numberedDownloadName(name, sequence) : name;
    try {
      await directory.getFileHandle(candidate);
    } catch (error) {
      if (error?.name !== 'NotFoundError') throw error;
      return directory.getFileHandle(candidate, { create: true });
    }
  }
  throw new Error('保存目录中存在过多同名文件');
}

async function createBatchDownloadWritable(rootDirectory, folderPath, name) {
  let directory = rootDirectory;
  for (const segment of normalizeFolderPath(folderPath).split('/').filter(Boolean)) {
    directory = await directory.getDirectoryHandle(segment, { create: true });
  }
  const handle = await availableDownloadFileHandle(directory, name);
  return handle.createWritable();
}

function androidFileBridge() {
  try {
    const bridge = window.YuniShareAndroid;
    return bridge
      && typeof bridge.prepareDownload === 'function'
      && typeof bridge.downloadState === 'function'
      && typeof bridge.writeChunk === 'function'
      && typeof bridge.finishDownload === 'function'
      && typeof bridge.cancelDownload === 'function'
      ? bridge
      : null;
  } catch {
    return null;
  }
}

async function createAndroidDownloadWritable(metadata, signal) {
  const bridge = androidFileBridge();
  if (!bridge) return null;
  const transferId = String(bridge.prepareDownload(
    String(metadata.name || 'Yuni-Share-download'),
    String(metadata.mime || 'application/octet-stream')
  ));
  while (true) {
    if (signal?.aborted) {
      bridge.cancelDownload(transferId);
      throw abortError();
    }
    const state = String(bridge.downloadState(transferId));
    if (state === 'ready') break;
    if (state === 'cancelled') throw abortError();
    if (state.startsWith('failed:')) throw new Error(state.slice(7) || '无法打开系统文件保存界面');
    await wait(150);
  }
  let settled = false;
  return {
    async write(value) {
      const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
      for (let offset = 0; offset < bytes.byteLength; offset += 128 * 1024) {
        if (signal?.aborted) throw abortError();
        const encoded = bytesToBase64url(bytes.subarray(offset, Math.min(bytes.byteLength, offset + 128 * 1024)));
        if (!bridge.writeChunk(transferId, encoded)) throw new Error('Android 文件保存写入失败');
      }
    },
    async close() {
      if (settled) return;
      if (!bridge.finishDownload(transferId)) throw new Error('Android 文件保存完成失败');
      settled = true;
    },
    async abort() {
      if (settled) return;
      bridge.cancelDownload(transferId);
      settled = true;
    }
  };
}

async function downloadEncryptedFile(item, button, { directoryHandle = null } = {}) {
  if (!item || !vaultKey) {
    openVaultModal('unlock');
    return false;
  }
  if (downloads.has(item.file.id)) {
    showToast('该文件正在下载');
    return false;
  }
  const originalText = button.title;
  let metadata;
  try {
    metadata = await decryptMetadata(item.file);
  } catch {
    showToast('无法解密文件元数据');
    return false;
  }
  const task = createDownloadTask({ ...item, metadata });
  button.disabled = true;
  button.title = '正在下载';
  try {
    const rawFileKey = base64urlToBytes(task.metadata.fileKey);
    task.metadata.fileKey = '';
    let fileKey;
    try {
      fileKey = await crypto.subtle.importKey('raw', rawFileKey, { name: 'AES-GCM' }, false, ['decrypt']);
    } finally {
      rawFileKey.fill(0);
    }
    const nonce = base64urlToBytes(task.metadata.fileNonce);
    const pieces = [];
    if (directoryHandle) {
      task.writable = await createBatchDownloadWritable(directoryHandle, item.path, task.metadata.name);
    } else if (androidFileBridge()) {
      task.writable = await createAndroidDownloadWritable(task.metadata, task.controller.signal);
    } else if ('showSaveFilePicker' in window) {
      const handle = await window.showSaveFilePicker({ suggestedName: task.metadata.name });
      if (task.cancelled) throw abortError();
      task.writable = await handle.createWritable();
    } else if (task.metadata.size > 512 * 1024 * 1024) {
      throw new Error('为避免浏览器占满内存，超过 512 MB 的加密下载请使用支持文件保存对话框的 Chromium 浏览器');
    }
    task.startedAt = performance.now();
    setDownloadState(task, '正在下载');
    task.row.querySelector('[data-download-speed]').textContent = task.writable ? '逐片解密并写入设备' : '逐片解密中';

    const CONCURRENCY = Math.min(transferConcurrency(), task.chunkCount);
    const chunkPromises = new Map();
    const chunkProgress = new Map();

    function scheduleFetch(idx) {
      if (idx >= task.chunkCount || chunkPromises.has(idx)) return;
      const expectedPlainBytes = Math.max(0, Math.min(
        task.metadata.plainChunkSize,
        task.metadata.size - idx * task.metadata.plainChunkSize
      ));
      const p = (async () => {
        const ciphertext = await retryWhileOnline(() => fetchEncryptedChunkWithProgress(item.file.id, idx, task.controller.signal, receivedBytes => {
          const pb = Math.min(expectedPlainBytes, Math.max(0, receivedBytes - GCM_TAG_BYTES));
          chunkProgress.set(idx, pb);
          task.partialBytes = [...chunkProgress.values()].reduce((sum, v) => sum + v, 0);
          updateDownloadProgress(task);
        }), {
          signal: task.controller.signal,
          onRetry: (attempt, delay) => {
            task.retrying = true;
            setDownloadState(task, '分片重试 ' + attempt);
            task.row.querySelector('[data-download-speed]').textContent = Math.ceil(delay / 1000) + ' 秒后继续';
          }
        });
        if (task.cancelled) throw abortError();
        const decrypted = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: chunkIv(nonce, idx), additionalData: chunkAad(item.file.upload_id, idx) },
          fileKey,
          ciphertext
        );
        chunkProgress.delete(idx);
        const plaintext = await decodeFileChunk(decrypted, task.metadata, expectedPlainBytes);
        return { plaintext, byteLength: plaintext.byteLength };
      })();
      chunkPromises.set(idx, p);
    }

    for (let i = 0; i < Math.min(CONCURRENCY, task.chunkCount); i += 1) {
      scheduleFetch(i);
    }

    for (let index = 0; index < task.chunkCount; index += 1) {
      if (task.cancelled) throw abortError();
      if (index + CONCURRENCY < task.chunkCount) {
        scheduleFetch(index + CONCURRENCY);
      }

      const chunkResult = await chunkPromises.get(index);
      chunkPromises.delete(index);
      if (task.cancelled) throw abortError();

      const { plaintext, byteLength } = chunkResult;
      task.writing = true;
      setDownloadState(task, '正在写入');
      if (task.writable) {
        const plaintextBytes = new Uint8Array(plaintext);
        try {
          await task.writable.write(plaintextBytes);
        } finally {
          plaintextBytes.fill(0);
        }
      } else {
        pieces.push(plaintext);
      }
      task.writing = false;
      task.completedBytes += byteLength;
      task.partialBytes = [...chunkProgress.values()].reduce((sum, v) => sum + v, 0);
      task.completedChunks += 1;
      updateDownloadProgress(task);
    }

    if (task.completedBytes !== task.metadata.size) throw new Error('下载内容大小校验失败');
    if (task.writable) await task.writable.close();
    else {
      const url = URL.createObjectURL(new Blob(pieces, { type: task.metadata.mime || 'application/octet-stream' }));
      const link = document.createElement('a');
      link.href = url;
      link.download = task.metadata.name;
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    }
    task.settled = true;
    task.row.querySelector('.cancel-download').disabled = true;
    task.row.querySelector('[data-download-speed]').textContent = '已保存到设备';
    setDownloadState(task, '下载完成');
    showToast(task.metadata.name + ' 已解密下载');
    await removeDownloadTask(task, 1200);
    return true;
  } catch (error) {
    if (task.cancelled || isAbortError(error)) {
      if (!task.cancelPromise) await cancelDownload(task);
      else await task.cancelPromise;
      return false;
    }
    if (typeof task.writable?.abort === 'function') {
      await Promise.resolve(task.writable.abort()).catch(() => {});
    }
    task.settled = true;
    task.row.querySelector('.cancel-download').disabled = true;
    task.row.querySelector('[data-download-speed]').textContent = error.message || '下载失败';
    setDownloadState(task, '下载失败', true);
    showToast(error.message || '下载失败');
    await removeDownloadTask(task, 4500);
    return false;
  } finally {
    button.disabled = false;
    button.title = originalText;
  }
}

async function deleteFileIds(ids, { reload = true } = {}) {
  const uniqueIds = [...new Set(ids)];
  if (!uniqueIds.length) return 0;
  const failed = [];
  for (let offset = 0; offset < uniqueIds.length; offset += 500) {
    const batch = uniqueIds.slice(offset, offset + 500);
    const result = await api('/api/files/batch-delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: batch })
    });
    failed.push(...(result.failed || []));
    for (const id of result.deleted || []) selectedFileIds.delete(id);
  }
  if (reload) {
    me = await api('/api/me');
    updateStorage();
    await loadFiles();
  }
  if (failed.length) throw new Error('有 ' + failed.length + ' 个文件未能删除，请稍后重试');
  return uniqueIds.length;
}

async function downloadFileIds(ids) {
  if (!vaultKey) {
    openVaultModal('unlock');
    return;
  }
  const items = [...new Set(ids)].map(id => listedFiles.get(id)).filter(item => item?.encrypted && !item.locked)
    .sort((left, right) => (left.path + '/' + left.name).localeCompare(right.path + '/' + right.name, 'zh-CN'));
  if (!items.length) throw new Error('没有可下载的已解锁文件');
  if (!('showDirectoryPicker' in window)) {
    throw new Error('批量下载需要使用支持目录选择的 Chrome 或 Edge 浏览器');
  }
  let directoryHandle;
  try {
    directoryHandle = await window.showDirectoryPicker({
      id: 'yuni-share-batch-download',
      mode: 'readwrite',
      startIn: 'downloads'
    });
  } catch (error) {
    if (isAbortError(error)) return 0;
    throw error;
  }
  const control = document.createElement('button');
  control.title = '批量下载';
  let completed = 0;
  for (const item of items) {
    if (await downloadEncryptedFile(item, control, { directoryHandle })) completed += 1;
  }
  showToast(completed + ' / ' + items.length + ' 个文件已保存到所选目录');
  return completed;
}

$('#loginTab').addEventListener('click', () => setMode('login'));
$('#registerTab').addEventListener('click', () => setMode('register'));
$('#passkeyLogin').addEventListener('click', async () => {
  const button = $('#passkeyLogin');
  button.disabled = true;
  $('#authError').textContent = '';
  try {
    await loginWithPasskey();
  } catch (error) {
    $('#authError').textContent = isPasskeyCancellation(error)
      ? ''
      : passkeySetupError(error).message;
  } finally {
    button.disabled = false;
  }
});
$('#sendCode').addEventListener('click', async () => {
  const form = Object.fromEntries(new FormData(authForm));
  $('#authError').textContent = '';
  try {
    const endpoint = authMode === 'legacy' ? '/api/legacy/code' : '/api/register/code';
    const data = await api(endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(form) });
    startCodeCountdown(data.retryAfterSeconds);
    showToast('验证码已发送，请检查邮箱');
  } catch (error) {
    $('#authError').textContent = error.message;
  }
});

authForm.addEventListener('submit', async event => {
  event.preventDefault();
  const button = $('#authSubmit');
  button.disabled = true;
  $('#authError').textContent = '';
  let createdVault = null;
  let recommendPasskeyAfterRegistration = false;
  try {
    const form = Object.fromEntries(new FormData(authForm));
    if (authMode === 'register') {
      recommendPasskeyAfterRegistration = true;
      createdVault = await createVaultConfig(String(form.vaultPassword || ''));
      form.encryption = createdVault.config;
      form.clientVersion = 2;
      delete form.vaultPassword;
    }
    const endpoint = authMode === 'legacy' ? '/api/legacy/bind' : '/api/' + authMode;
    await api(endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(form) });
    authForm.reset();
    await loadSession({ key: createdVault?.key });
    if (recommendPasskeyAfterRegistration && me?.encryption && !me.encryption.passkeys?.length) {
      openVaultPasskeyRecommendation();
    }
  } catch (error) {
    $('#authError').textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

for (const toggle of document.querySelectorAll('[data-password-toggle]')) {
  toggle.addEventListener('click', () => {
    const input = document.getElementById(toggle.dataset.passwordToggle);
    if (!input) return;
    const revealed = input.type === 'password';
    input.type = revealed ? 'text' : 'password';
    toggle.classList.toggle('is-visible', revealed);
    toggle.setAttribute('aria-pressed', String(revealed));
    const label = input.name === 'vaultPassword' ? '加密密码' : '密码';
    const action = revealed ? '隐藏' : '显示';
    toggle.setAttribute('aria-label', action + label);
    toggle.setAttribute('title', action + label);
  });
}

$('#forgotPassword').addEventListener('click', openPasswordResetRequestModal);
$('#closePasswordResetRequestModal').addEventListener('click', closePasswordResetRequestModal);
$('#passwordResetRequestForm').addEventListener('submit', async event => {
  event.preventDefault();
  const button = $('#passwordResetRequestSubmit');
  button.disabled = true;
  $('#passwordResetRequestError').textContent = '';
  try {
    await api('/api/password-reset/request', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: $('#passwordResetEmail').value })
    });
    closePasswordResetRequestModal();
    showToast('若该邮箱已关联账户，重置邮件已发送');
  } catch (error) {
    $('#passwordResetRequestError').textContent = error.message || '无法发送重置邮件';
  } finally {
    button.disabled = false;
  }
});
$('#closePasswordResetModal').addEventListener('click', closePasswordResetModal);
$('#passwordResetForm').addEventListener('submit', async event => {
  event.preventDefault();
  const button = $('#passwordResetSubmit');
  const password = $('#passwordResetPassword').value;
  button.disabled = true;
  $('#passwordResetError').textContent = '';
  try {
    if (password !== $('#passwordResetConfirm').value) throw new Error('两次输入的新登录密码不一致');
    const result = await api('/api/password-reset/complete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: $('#passwordResetToken').value, password })
    });
    closePasswordResetModal();
    if (result.signedIn) {
      await loadSession();
      showToast('登录密码已更新，请解锁加密空间');
    } else {
      setMode('login');
      showToast('登录密码已更新。该账户仍在删除流程中，请使用删除确认邮件撤销删除。');
    }
  } catch (error) {
    $('#passwordResetError').textContent = error.message || '无法更新登录密码';
  } finally {
    button.disabled = false;
  }
});
$('#logout').addEventListener('click', async () => {
  await api('/api/logout', { method: 'POST' });
  vaultKey = null;
  await loadSession();
});

$('#fileInput').addEventListener('change', event => {
  enqueueFiles(uploadEntriesFromFileList(event.target.files));
  event.target.value = '';
});
$('#folderInput').addEventListener('change', event => {
  enqueueFiles(uploadEntriesFromFileList(event.target.files));
  event.target.value = '';
});
$('#dropZone').addEventListener('click', () => {
  if (!$('#fileInput').disabled) $('#fileInput').click();
});
$('#pickFiles').addEventListener('click', event => {
  event.stopPropagation();
  $('#fileInput').click();
});
$('#pickFolder').addEventListener('click', event => {
  event.stopPropagation();
  $('#folderInput').click();
});
$('#dropZone').addEventListener('keydown', event => {
  if (event.key !== 'Enter' && event.key !== ' ') return;
  event.preventDefault();
  $('#fileInput').click();
});
for (const type of ['dragenter', 'dragover']) {
  $('#dropZone').addEventListener(type, event => {
    event.preventDefault();
    $('#dropZone').classList.add('dragging');
  });
}
for (const type of ['dragleave', 'drop']) {
  $('#dropZone').addEventListener(type, event => {
    event.preventDefault();
    $('#dropZone').classList.remove('dragging');
  });
}
$('#dropZone').addEventListener('drop', async event => {
  try {
    await enqueueFiles(await uploadEntriesFromDrop(event.dataTransfer));
  } catch (error) {
    showToast(error.message || '无法读取拖放的文件夹');
  }
});

$('#vaultStatus').addEventListener('click', event => {
  const action = event.target.closest('[data-vault-action]')?.dataset.vaultAction;
  if (action === 'lock') lockVault();
  else if (action === 'passkeys') openVaultPasskeyModal();
  else if (action === 'unlock-passkey') {
    unlockWithVaultPasskey().catch(error => {
      if (!isPasskeyCancellation(error)) showToast(passkeySetupError(error).message);
    });
  } else if (action) openVaultModal(action);
});
$('#accountDelete').addEventListener('click', openAccountDeletionModal);
$('#renameUsernameForm').addEventListener('submit', async event => {
  event.preventDefault();
  const button=event.currentTarget.querySelector('button');button.disabled=true;
  const status=$('#renameUsernameStatus');status.textContent='正在保存…';
  try {
    await api('/api/profile/username',{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:$('#newUsername').value.trim()})});
    await loadSession({key:vaultKey});status.textContent='用户名已更新';
  } catch(error) {status.textContent=error.message;}
  finally {button.disabled=false;}
});
$('#subscription').addEventListener('click', openSubscriptionModal);
$('#closeSubscriptionModal').addEventListener('click', () => { $('#subscriptionModal').hidden = true; });
$('#subscriptionModal').addEventListener('click', event => {
  const button = event.target.closest('[data-plan-id]');
  if (!button) return;
  void startSubscriptionCheckout(button);
});
$('#closePaymentModal').addEventListener('click', () => { $('#paymentModal').hidden = true; clearInterval(paymentPollTimer); paymentPollTimer = null; });
$('#avatarButton').addEventListener('click', () => $('#avatarInput').click());
$('#mobileAvatarButton').addEventListener('click', () => $('#avatarInput').click());
$('#avatarInput').addEventListener('change', async event => {
  const file = event.target.files?.[0]; event.target.value = ''; if (!file) return;
  if (!['image/png', 'image/jpeg', 'image/webp'].includes(file.type)) return showToast('头像仅支持 PNG、JPEG 或 WebP', 'error');
  const dataUrl = await new Promise((resolve, reject) => { const reader = new FileReader(); reader.onload = () => resolve(reader.result); reader.onerror = reject; reader.readAsDataURL(file); });
  try { const result = await api('/api/profile/avatar', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ dataUrl }) }); $('#accountAvatar').src = result.avatarUrl; $('#mobileAccountAvatar').src = result.avatarUrl; me.avatarUrl = result.avatarUrl; showToast('头像已更新'); }
  catch (error) { showToast(error.message, 'error'); }
});
$('#closeAccountDeletionModal').addEventListener('click', closeAccountDeletionModal);
$('#cancelAccountDeletion').addEventListener('click', closeAccountDeletionModal);
$('#accountDeletionUsePassword').addEventListener('click', useAccountDeletionPassword);
$('#accountDeletionSwitchToPasskey').addEventListener('click', useAccountDeletionPasskey);
$('#accountDeletionUsePasskey').addEventListener('click', async () => {
  const button = $('#accountDeletionUsePasskey');
  button.disabled = true;
  $('#accountDeletionError').textContent = '';
  try {
    accountDeletionPasskeyProof = await verifyAccountDeletionWithPasskey();
    $('#accountDeletionPassword').value = '';
    $('#accountDeletionPasswordField').hidden = true;
    $('#accountDeletionPassword').required = false;
    const section = $('#accountDeletionPasskeyVerification');
    section.classList.add('is-verified');
    section.querySelector('strong').textContent = 'Passkey 已验证';
    section.querySelector('span').textContent = '验证仅用于本次删除申请，会话绑定且将在 5 分钟后失效。';
    button.textContent = 'Passkey 已验证';
    showToast('Passkey 已验证，可以安排删除');
  } catch (error) {
    accountDeletionPasskeyProof = '';
    if (!isPasskeyCancellation(error)) $('#accountDeletionError').textContent = passkeySetupError(error).message;
    button.disabled = false;
  }
});
$('#accountDeletionForm').addEventListener('submit', async event => {
  event.preventDefault();
  const button = $('#accountDeletionSubmit');
  const passkeyProof = accountDeletionPasskeyProof;
  const password = $('#accountDeletionPassword').value;
  button.disabled = true;
  $('#accountDeletionError').textContent = '';
  try {
    if (!passkeyProof && password.length < 10) {
      throw new Error('请使用 Passkey 验证，或输入账户登录密码');
    }
    const result = await api('/api/account-deletion', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        retentionDays: Number(document.querySelector('input[name="accountDeletionDays"]:checked')?.value),
        password,
        passkeyProof
      })
    });
    closeAccountDeletionModal();
    vaultKey = null;
    await loadSession();
    showToast('删除确认邮件已发送；账户将在 ' + formatDate(result.scheduledFor) + ' 删除');
  } catch (error) {
    if (passkeyProof) {
      $('#accountDeletionPasswordField').hidden = true;
      $('#accountDeletionPassword').required = false;
      resetAccountDeletionPasskeyVerification();
    }
    $('#accountDeletionError').textContent = error.message || '无法提交删除申请';
  } finally {
    button.disabled = false;
  }
});
$('#closeCancelDeletionModal').addEventListener('click', closeCancelDeletionModal);
$('#cancelDeletionForm').addEventListener('submit', async event => {
  event.preventDefault();
  const button = $('#cancelDeletionSubmit');
  button.disabled = true;
  $('#cancelDeletionError').textContent = '';
  try {
    await api('/api/account-deletion/cancel', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token: $('#cancelDeletionToken').value
      })
    });
    closeCancelDeletionModal();
    await loadSession();
    showToast('账户删除已撤销，请解锁加密空间');
  } catch (error) {
    $('#cancelDeletionError').textContent = error.message || '无法撤销删除';
  } finally {
    button.disabled = false;
  }
});
$('#closeConfirmModal').addEventListener('click', () => closeConfirmModal(false));
$('#confirmCancel').addEventListener('click', () => closeConfirmModal(false));
$('#confirmAccept').addEventListener('click', () => closeConfirmModal(true));
$('#closeVaultModal').addEventListener('click', closeVaultModal);
$('#vaultUnlockPasskey').addEventListener('click', async () => {
  const button = $('#vaultUnlockPasskey');
  button.disabled = true;
  $('#vaultError').textContent = '';
  try {
    await unlockWithVaultPasskey();
    closeVaultModal();
    void resumePendingUploads().catch(error => showToast(error.message || '无法继续上传', 'error'));
  }
  catch (error) { if (!isPasskeyCancellation(error)) $('#vaultError').textContent = passkeySetupError(error).message; }
  finally { button.disabled = false; }
});
$('#closeVaultPasskeyModal').addEventListener('click', closeVaultPasskeyModal);
$('#skipVaultPasskeyRecommendation').addEventListener('click', closeVaultPasskeyRecommendation);
$('#startVaultPasskeyRecommendation').addEventListener('click', async () => {
  const button = $('#startVaultPasskeyRecommendation');
  if (!pendingPasskeyRecommendation) return;
  button.disabled = true;
  $('#vaultPasskeyRecommendationError').textContent = '';
  try {
    closeVaultPasskeyRecommendation();
    openVaultPasskeyModal();
  } catch (error) {
    if (!isPasskeyCancellation(error)) $('#vaultPasskeyRecommendationError').textContent = passkeySetupError(error).message;
  } finally {
    button.disabled = false;
  }
});
$('#vaultPasskeyUsePassword').addEventListener('click', useVaultPasskeyPassword);
$('#vaultPasskeySwitchToPasskey').addEventListener('click', useVaultPasskeyPasskey);
$('#vaultPasskeyUsePasskey').addEventListener('click', async () => {
  const button = $('#vaultPasskeyUsePasskey');
  button.disabled = true;
  $('#vaultPasskeyError').textContent = '';
  try {
    const verified = await verifyVaultPasskeyManagement({ requireVaultKey: true });
    clearVaultPasskeyManagementMaterial();
    vaultPasskeyManagementProof = verified.passkeyProof;
    vaultPasskeyManagementKey = verified.rawVaultKey;
    const section = $('#vaultPasskeyVerification');
    section.classList.add('is-verified');
    section.querySelector('strong').textContent = 'Passkey 已验证';
    section.querySelector('span').textContent = '此验证仅用于添加新的 Passkey，并且仅在当前会话中短暂有效。';
    button.textContent = 'Passkey 已验证';
    $('#vaultPasskeyAccountPasswordField').hidden = true;
    $('#vaultPasskeyEncryptionPasswordField').hidden = true;
    $('#vaultPasskeyAccountPassword').required = false;
    $('#vaultPasskeyEncryptionPassword').required = false;
    showToast('Passkey 已验证，可以添加新的 Passkey');
  } catch (error) {
    clearVaultPasskeyManagementMaterial();
    if (!isPasskeyCancellation(error)) $('#vaultPasskeyError').textContent = passkeySetupError(error).message;
    button.disabled = false;
  }
});
$('#vaultPasskeyList').addEventListener('click', event => {
  const button = event.target.closest('.remove-vault-passkey');
  if (button) openVaultPasskeyRemoval(button.dataset.credentialId);
});
$('#cancelVaultPasskeyRemove').addEventListener('click', cancelVaultPasskeyRemoval);
$('#vaultPasskeyRemoveUsePassword').addEventListener('click', useVaultPasskeyRemovalPassword);
$('#vaultPasskeyRemoveSwitchToPasskey').addEventListener('click', useVaultPasskeyRemovalPasskey);
$('#vaultPasskeyRemoveUsePasskey').addEventListener('click', async () => {
  const button = $('#vaultPasskeyRemoveUsePasskey');
  button.disabled = true;
  $('#vaultPasskeyRemoveError').textContent = '';
  try {
    const verified = await verifyVaultPasskeyManagement();
    vaultPasskeyRemovalProof = verified.passkeyProof;
    const section = $('#vaultPasskeyRemoveVerification');
    section.classList.add('is-verified');
    section.querySelector('strong').textContent = 'Passkey 已验证';
    section.querySelector('span').textContent = '此验证仅用于本次移除操作，并且仅在当前会话中短暂有效。';
    button.textContent = 'Passkey 已验证';
    $('#vaultPasskeyRemovePasswordField').hidden = true;
    $('#vaultPasskeyRemovePassword').required = false;
    showToast('Passkey 已验证，可以移除 Passkey');
  } catch (error) {
    vaultPasskeyRemovalProof = '';
    if (!isPasskeyCancellation(error)) $('#vaultPasskeyRemoveError').textContent = passkeySetupError(error).message;
    button.disabled = false;
  }
});
$('#vaultPasskeyForm').addEventListener('submit', async event => {
  event.preventDefault();
  const button = $('#vaultPasskeySubmit');
  const accountPassword = $('#vaultPasskeyAccountPassword').value;
  const encryptionPassword = $('#vaultPasskeyEncryptionPassword').value;
  const passkeyProof = vaultPasskeyManagementProof;
  const rawVaultKey = vaultPasskeyManagementKey;
  let completed = false;
  button.disabled = true;
  $('#vaultPasskeyError').textContent = '';
  try {
    await addVaultPasskey({
      accountPassword,
      encryptionPassword,
      passkeyProof,
      rawVaultKey,
      preference: $('#vaultPasskeyPreference').value
    });
    completed = true;
    closeVaultPasskeyModal();
    showToast('Passkey 创建完成');
  } catch (error) {
    if (!isPasskeyCancellation(error)) $('#vaultPasskeyError').textContent = passkeySetupError(error).message;
  } finally {
    if (!completed) {
      clearVaultPasskeyManagementMaterial();
      if (passkeyProof) resetVaultPasskeyVerification();
      $('#vaultPasskeyAccountPassword').value = '';
      $('#vaultPasskeyEncryptionPassword').value = '';
      button.disabled = !webauthnSupported();
    }
  }
});
$('#vaultPasskeyRemoveForm').addEventListener('submit', async event => {
  event.preventDefault();
  const button = $('#vaultPasskeyRemoveSubmit');
  const credentialId = $('#vaultPasskeyRemoveId').value;
  const password = $('#vaultPasskeyRemovePassword').value;
  const passkeyProof = vaultPasskeyRemovalProof;
  button.disabled = true;
  $('#vaultPasskeyRemoveError').textContent = '';
  try {
    if (!await confirmAction({
      eyebrow: 'Passkey',
      title: '移除此 Passkey？',
      message: '移除后，此设备、密码管理器或安全密钥将不能再解锁该加密空间。',
      confirmLabel: '移除'
    })) return;
    await api('/api/vault-passkeys/' + encodeURIComponent(credentialId), {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password, passkeyProof })
    });
    me = await api('/api/me');
    renderVaultStatus();
    renderVaultPasskeyList();
    cancelVaultPasskeyRemoval();
    showToast('Passkey 已移除');
  } catch (error) {
    $('#vaultPasskeyRemoveError').textContent = error.message || '无法移除 Passkey';
  } finally {
    vaultPasskeyRemovalProof = '';
    if (passkeyProof) resetVaultPasskeyRemovalVerification();
    button.disabled = false;
  }
});
$('#vaultForm').addEventListener('submit', async event => {
  event.preventDefault();
  const button = $('#vaultSubmit');
  const mode = $('#vaultModal').dataset.mode;
  const passphrase = $('#vaultPassword').value;
  button.disabled = true;
  $('#vaultError').textContent = '';
  try {
    if (mode === 'setup') {
      if (passphrase.length < 12) throw new Error('请输入至少 12 个字符的加密密码');
      const accountPassword = $('#vaultAccountPassword').value;
      if (accountPassword.length < 10) throw new Error('请输入账户登录密码以确认设置');
      if (passphrase !== $('#vaultPasswordConfirmModal').value) throw new Error('两次输入的加密密码不一致');
      const createdVault = await createVaultConfig(passphrase);
      await api('/api/encryption/setup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: accountPassword, encryption: createdVault.config, clientVersion: 2 })
      });
      me = await api('/api/me');
      vaultKey = createdVault.key;
      renderVaultStatus();
      await loadFiles();
      await refreshRemoteUploads();
      showToast('端到端加密空间已创建');
    } else if (mode === 'change') {
      const accountPassword = $('#vaultAccountPassword').value;
      const newPassphrase = $('#vaultNewPassword').value;
      if (passphrase.length < 12 || newPassphrase.length < 12) throw new Error('加密密码至少需要 12 个字符');
      if (newPassphrase !== $('#vaultPasswordConfirmModal').value) throw new Error('两次输入的新加密密码不一致');
      if (accountPassword.length < 10) throw new Error('请输入登录密码以确认修改');
      const rawVaultKey = await unwrapVaultKey(passphrase, me.encryption);
      let encryption;
      try {
        encryption = await wrapVaultKey(rawVaultKey, newPassphrase);
      } finally {
        rawVaultKey.fill(0);
      }
      await api('/api/encryption/password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: accountPassword, encryption })
      });
      me = await api('/api/me');
      renderVaultStatus();
      showToast('加密密码已更新，文件未被改动');
    } else if (mode === 'recover') {
      const accountPassword = $('#vaultAccountPassword').value;
      const newPassphrase = $('#vaultNewPassword').value;
      const recoveryPassword = $('#vaultRecoveryPassword').value;
      if (newPassphrase.length < 12) throw new Error('新加密密码至少需要 12 个字符');
      if (newPassphrase !== $('#vaultPasswordConfirmModal').value) throw new Error('两次输入的新加密密码不一致');
      if (accountPassword.length < 10) throw new Error('请输入登录密码以确认恢复');
      if (recoveryPassword.length < 12) throw new Error('请输入至少 12 个字符的恢复密码');
      const rawVaultKey = await unwrapVaultWithRecovery(recoveryPassword, me.encryption.recovery);
      let encryption;
      let recoveredKey;
      try {
        [encryption, recoveredKey] = await Promise.all([
          wrapVaultKey(rawVaultKey, newPassphrase),
          importVaultKey(rawVaultKey)
        ]);
      } finally {
        rawVaultKey.fill(0);
      }
      await api('/api/encryption/password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: accountPassword, encryption })
      });
      me = await api('/api/me');
      vaultKey = recoveredKey;
      renderVaultStatus();
      await loadFiles();
      revealFilesAfterUnlock();
      await refreshRemoteUploads();
      showToast('加密空间已恢复');
    } else if (mode === 'reset-recovery') {
      const recoveryPassword = $('#vaultRecoveryPassword').value;
      if (recoveryPassword.length < 12) throw new Error('恢复密码至少需要 12 个字符');
      if (recoveryPassword !== $('#vaultRecoveryPasswordConfirm').value) throw new Error('两次输入的恢复密码不一致');
      const { rawVaultKey, passkeyProof } = await passkeyMaterialForPasskeyReset('recovery');
      let recovery;
      try {
        recovery = await wrapVaultKey(rawVaultKey, recoveryPassword, vaultRecoveryAad());
      } finally {
        rawVaultKey.fill(0);
      }
      await api('/api/encryption/recovery-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recovery, passkeyProof })
      });
      me = await api('/api/me');
      renderVaultStatus();
      showToast('恢复密码已重设。旧恢复密码无法再使用。');
    } else if (mode === 'set-recovery') {
      const accountPassword = $('#vaultAccountPassword').value;
      if (passphrase.length < 12) throw new Error('请输入当前加密密码');
      if (accountPassword.length < 10) throw new Error('请输入登录密码以确认生成');
      const recoveryPassword = $('#vaultRecoveryPassword').value;
      if (recoveryPassword.length < 12) throw new Error('恢复密码至少需要 12 个字符');
      if (recoveryPassword !== $('#vaultRecoveryPasswordConfirm').value) throw new Error('两次输入的恢复密码不一致');
      if (passphrase === recoveryPassword) throw new Error('恢复密码应与加密密码不同');
      const rawVaultKey = await unwrapVaultKey(passphrase, me.encryption);
      let recovery;
      try {
        recovery = await wrapVaultKey(rawVaultKey, recoveryPassword, vaultRecoveryAad());
      } finally {
        rawVaultKey.fill(0);
      }
      await api('/api/encryption/recovery-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: accountPassword, recovery })
      });
      me = await api('/api/me');
      renderVaultStatus();
      showToast('恢复密码已设置');
    } else if (mode === 'reset-with-passkey') {
      const newPassphrase = $('#vaultNewPassword').value;
      if (newPassphrase.length < 12) throw new Error('新加密密码至少需要 12 个字符');
      if (newPassphrase !== $('#vaultPasswordConfirmModal').value) throw new Error('两次输入的新加密密码不一致');
      const { rawVaultKey, passkeyProof } = await passkeyMaterialForPasskeyReset('password');
      let encryption;
      let recoveredKey;
      try {
        [encryption, recoveredKey] = await Promise.all([
          wrapVaultKey(rawVaultKey, newPassphrase),
          importVaultKey(rawVaultKey)
        ]);
      } finally {
        rawVaultKey.fill(0);
      }
      await api('/api/encryption/password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ encryption, passkeyProof })
      });
      me = await api('/api/me');
      vaultKey = recoveredKey;
      renderVaultStatus();
      await loadFiles();
      revealFilesAfterUnlock();
      await refreshRemoteUploads();
      showToast('加密密码已通过 Passkey 重设，文件未被改动');
    } else {
      if (passphrase.length < 12) throw new Error('请输入至少 12 个字符的加密密码');
      vaultKey = await unlockVault(passphrase, me.encryption);
      renderVaultStatus();
      await loadFiles();
      revealFilesAfterUnlock();
      await refreshRemoteUploads();
      closeVaultModal();
      void resumePendingUploads().catch(error => showToast(error.message || '无法继续上传', 'error'));
      showToast('加密空间已解锁');
    }
    if (vaultKey) resolvePendingVaultUnlock();
    closeVaultModal();
  } catch (error) {
    if (mode === 'setup' || mode === 'unlock') vaultKey = null;
    renderVaultStatus();
    if (!isPasskeyCancellation(error)) $('#vaultError').textContent = error.message || '无法完成加密空间操作';
  } finally {
    $('#vaultPassword').value = '';
    $('#vaultNewPassword').value = '';
    $('#vaultAccountPassword').value = '';
    $('#vaultPasswordConfirmModal').value = '';
    $('#vaultRecoveryPassword').value = '';
    $('#vaultRecoveryPasswordConfirm').value = '';
    button.disabled = false;
  }
});

$('#closeFileManageModal').addEventListener('click', closeFileManageModal);
$('#cancelFileManage').addEventListener('click', closeFileManageModal);
$('#fileManageForm').addEventListener('submit', async event => {
  event.preventDefault();
  const mode = $('#fileManageModal').dataset.mode;
  const item = listedFiles.get(managedFileId);
  if (mode !== 'move-folder' && mode !== 'rename-folder' && !item) return closeFileManageModal();
  const button = $('#fileManageSubmit');
  button.disabled = true;
  $('#fileManageError').textContent = '';
  try {
    if (mode === 'move-folder') {
      const destPath = normalizeFolderPath($('#fileMoveSelect').value);
      await moveEncryptedFolder(managedFolderPath, $('#fileMoveSelect').value);
      const targetDisplay = destPath ? destPath : '根目录';
      showToast('文件夹已移动到 ' + targetDisplay);
    } else if (mode === 'rename-folder') {
      const name = $('#fileRenameInput').value.trim();
      await renameEncryptedFolder(managedFolderPath, name);
      showToast('文件夹已重命名为 ' + name);
    } else if (mode === 'rename') {
      let name = $('#fileRenameInput').value.trim();
      const originalExt = extractFileExtension(item.name);
      const newExt = extractFileExtension(name);
      if (originalExt && !newExt) {
        name = name + originalExt;
      }
      if (!fileNameIsValid(name)) throw new Error('文件名不能为空，且不能包含斜杠或控制字符');
      if (name === item.name) throw new Error('文件名没有变化');
      await updateEncryptedFileMetadata(item, { name });
      showToast('文件已重命名为 ' + name);
    } else {
      const path = normalizeFolderPath($('#fileMoveSelect').value);
      if (path === item.path) throw new Error('文件已经在这个目录中');
      await updateEncryptedFileMetadata(item, { path });
      const targetDisplay = path ? path : '根目录';
      showToast('文件已移动到 ' + targetDisplay);
    }
    closeFileManageModal();
    await loadFiles();
  } catch (error) {
    $('#fileManageError').textContent = error.message || '无法更新文件';
  } finally {
    button.disabled = false;
  }
});

$('#createEmptyFolder').addEventListener('click', () => { void requestCreateItem('folder'); });
$('#createEmptyFile').addEventListener('click', () => { void requestCreateItem('file'); });
$('#closeCreateItemModal').addEventListener('click', closeCreateItemModal);
$('#cancelCreateItem').addEventListener('click', closeCreateItemModal);
$('#createItemModal').addEventListener('click', event => {
  if (event.target === event.currentTarget) closeCreateItemModal();
});
$('#createItemForm').addEventListener('submit', async event => {
  event.preventDefault();
  const mode = $('#createItemModal').dataset.mode;
  let name = $('#createItemName').value.trim();
  const button = $('#createItemSubmit');
  $('#createItemError').textContent = '';
  if (!fileNameIsValid(name)) {
    $('#createItemError').textContent = '名称不能为空，且不能包含斜杠或控制字符';
    return;
  }
  button.disabled = true;
  try {
    if (mode === 'folder') {
      const folderPath = joinFolderPath(currentDirectory, name);
      if (knownFolders.includes(folderPath)) throw new Error('当前目录已存在同名文件夹');
      const id = crypto.randomUUID();
      const encryption = await encryptFolderMetadata(id, folderPath);
      await api('/api/folders', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id,
          isRoot: parentFolderPath(folderPath) === '',
          encryption: { version: ENCRYPTION_VERSION, ...encryption }
        })
      });
      closeCreateItemModal();
      await loadFiles();
      showToast('空文件夹已创建并加密保存');
    } else {
      // If user provided name without extension, default to .txt
      if (!name.includes('.')) {
        name += '.txt';
      }
      const duplicate = [...listedFiles.values()].some(item => item.path === currentDirectory && item.name === name);
      if (duplicate) throw new Error('当前目录已存在同名文件');
      const extension = name.split('.').pop()?.toLowerCase() || '';
      const mimeMap = {
        txt: 'text/plain',
        md: 'text/markdown',
        markdown: 'text/markdown',
        json: 'application/json',
        jsonl: 'application/x-jsonlines',
        csv: 'text/csv',
        tsv: 'text/tab-separated-values',
        xml: 'application/xml',
        yaml: 'text/yaml',
        yml: 'text/yaml',
        log: 'text/plain',
        ini: 'text/plain',
        conf: 'text/plain',
        css: 'text/css',
        js: 'text/javascript',
        mjs: 'text/javascript',
        cjs: 'text/javascript',
        ts: 'text/typescript',
        tsx: 'text/typescript',
        jsx: 'text/javascript',
        html: 'text/html',
        htm: 'text/html',
        py: 'text/x-python',
        sh: 'text/x-sh',
        bash: 'text/x-sh',
        sql: 'text/x-sql',
        java: 'text/x-java-source',
        c: 'text/x-c',
        cpp: 'text/x-c++',
        h: 'text/x-c',
        hpp: 'text/x-c++',
        go: 'text/x-go',
        rs: 'text/x-rust',
        vue: 'text/plain',
        svelte: 'text/plain',
        svg: 'image/svg+xml'
      };
      const mime = mimeMap[extension] || (isTextPreview({ name }, '') ? 'text/plain' : 'application/octet-stream');
      const uploadId = crypto.randomUUID();
      const rawFileKey = randomBytes(32);
      const fileNonce = randomBytes(8);
      const metadata = {
        version: ENCRYPTION_VERSION,
        name,
        path: currentDirectory,
        mime,
        size: 0,
        plainChunkSize: LEGACY_PLAINTEXT_CHUNK_SIZE,
        fileKey: bytesToBase64url(rawFileKey),
        fileNonce: bytesToBase64url(fileNonce)
      };
      const encryption = await encryptMetadata(uploadId, metadata);
      rawFileKey.fill(0);
      const category = listingCategory(fileCategory(name, mime));
      await api('/api/files/empty', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          uploadId,
          category,
          insideFolder: Boolean(currentDirectory),
          encryption: { version: ENCRYPTION_VERSION, ...encryption }
        })
      });
      closeCreateItemModal();
      await loadFiles();
      showToast('空文件已创建并加密保存');
    }
  } catch (error) {
    $('#createItemError').textContent = error.message || '无法创建';
  } finally {
    button.disabled = false;
  }
});

$('#folderBreadcrumb').addEventListener('click', event => {
  const button = event.target.closest('[data-folder-path]');
  if (!button) return;
  currentDirectory = normalizeFolderPath(button.dataset.folderPath);
  loadFiles().catch(error => showToast(error.message));
});

$('#selectVisibleFiles').addEventListener('change', event => {
  const checked = event.target.checked;
  for (const id of currentDirectoryFileIds()) {
    if (checked) selectedFileIds.add(id);
    else selectedFileIds.delete(id);
  }
  const visibleFolderControls = [...document.querySelectorAll('#fileList .file-select[data-folder-path]')];
  for (const control of visibleFolderControls) {
    const folderPath = normalizeFolderPath(control.dataset.folderPath);
    if (checked) {
      selectedFolderPaths.add(folderPath);
      for (const id of folderFileIds(folderPath)) selectedFileIds.add(id);
    } else {
      selectedFolderPaths.delete(folderPath);
      for (const id of folderFileIds(folderPath)) selectedFileIds.delete(id);
    }
  }
  syncRenderedSelectionControls();
});

$('#selectAllUploads').addEventListener('change', event => {
  selectedUploadIds = event.currentTarget.checked
    ? new Set([...uploads.values()].filter(task => !task.settled).map(task => task.id))
    : new Set();
  updateUploadBatchControls();
});

$('#cancelSelectedUploads').addEventListener('click', async () => {
  const tasks = [...selectedUploadIds].map(id => uploads.get(id)).filter(task => task && !task.settled);
  await Promise.all(tasks.map(cancelUpload));
});

$('#cancelAllUploads').addEventListener('click', async () => {
  const tasks = [...uploads.values()].filter(task => !task.settled);
  await Promise.all(tasks.map(cancelUpload));
});

$('#fileList').addEventListener('click', event => {
  const checkbox = event.target.closest('.file-select');
  if (!checkbox) return;
  const checked = checkbox.getAttribute('aria-checked') !== 'true';
  const ids = selectionIdsForControl(checkbox);
  const folderPath = checkbox.dataset.folderPath ? normalizeFolderPath(checkbox.dataset.folderPath) : null;
  if (folderPath) {
    if (checked) {
      selectedFolderPaths.add(folderPath);
    } else {
      selectedFolderPaths.delete(folderPath);
    }
  }
  for (const id of ids) {
    if (checked) selectedFileIds.add(id);
    else selectedFileIds.delete(id);
  }
  syncRenderedSelectionControls();
});

$('#downloadSelectedFiles').addEventListener('click', async event => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    await downloadFileIds([...selectedFileIds]);
  } catch (error) {
    showToast(error.message || '无法下载所选文件');
  } finally {
    updateBatchToolbar();
  }
});

$('#deleteSelectedFiles').addEventListener('click', async () => {
  const ids = [...selectedFileIds];
  const selectedFolders = [...(selectedFolderPaths || new Set())];
  if (!ids.length && !selectedFolders.length) {
    showToast('请先选择要删除的文件或文件夹');
    return;
  }

  const confirmed = await confirmAction({
    eyebrow: '批量删除',
    title: '永久删除所选内容？',
    message: '将永久删除所选的 ' + (ids.length ? ids.length + ' 个文件' : '') + (selectedFolders.length ? (ids.length ? ' 和 ' : '') + selectedFolders.length + ' 个文件夹' : '') + '，无法恢复。',
    confirmLabel: '永久删除'
  });
  if (!confirmed) return;

  const button = $('#deleteSelectedFiles');
  button.disabled = true;
  try {
    if (ids.length) {
      await deleteFileIds(ids, { reload: false });
    }

    const foldersToDelete = new Set(selectedFolders);
    for (const record of encryptedFolderRecordsByPath.values()) {
      const filesInFolder = folderFileIds(record.path);
      if (filesInFolder.length > 0 && filesInFolder.every(fid => ids.includes(fid))) {
        foldersToDelete.add(record.path);
      }
    }

    const recordsToDelete = [...encryptedFolderRecordsByPath.values()].filter(record =>
      [...foldersToDelete].some(folderPath => record.path === folderPath || record.path.startsWith(folderPath + '/'))
    );
    if (recordsToDelete.length) {
      const folderRecordIds = recordsToDelete.map(r => r.id);
      await api('/api/folders/batch-delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids: folderRecordIds })
      }).catch(async () => {
        await Promise.all(recordsToDelete.map(record => api('/api/folders/' + record.id, { method: 'DELETE' }).catch(() => {})));
      });
    }

    for (const folderPath of foldersToDelete) {
      knownFolders = knownFolders.filter(p => p !== folderPath && !p.startsWith(folderPath + '/'));
      encryptedFolderRecordsByPath.delete(folderPath);
    }

    selectedFileIds = new Set();
    selectedFolderPaths = new Set();
    me = await api('/api/me');
    updateStorage();
    await loadFiles();
    showToast('已永久删除所选内容');
  } catch (error) {
    showToast(error.message || '批量删除失败');
  } finally {
    button.disabled = false;
    updateBatchToolbar();
  }
});

for (const id of ['closePreviewModal', 'previewClose']) {
  $('#' + id).addEventListener('click', requestClosePreviewModal);
}
$('#previewDownload').addEventListener('click', async event => {
  const item = listedFiles.get(previewFileId);
  if (!item) return;
  await downloadEncryptedFile(item, event.currentTarget);
});

$('#fileList').addEventListener('click', async event => {
  if (event.target.closest('.file-select')) return;
  const mobileActionMenu = event.target.closest('.file-actions-mobile');
  if (mobileActionMenu && event.target.closest('button, a')) mobileActionMenu.removeAttribute('open');
  const folderDelete = event.target.closest('.delete-folder');
  if (folderDelete) {
    const folderPath = normalizeFolderPath(folderDelete.dataset.folderPath);
    const ids = folderFileIds(folderPath);
    const confirmed = await confirmAction({
      eyebrow: '删除文件夹',
      title: '永久删除此文件夹？',
      message: '“' + folderDelete.dataset.name + '”中的 ' + ids.length + ' 个加密文件将被永久删除，无法恢复。',
      confirmLabel: '永久删除'
    });
    if (!confirmed) return;
    folderDelete.disabled = true;
    try {
      const count = await deleteEncryptedFolder(folderPath);
      showToast('文件夹及其中 ' + count + ' 个文件已删除');
    } catch (error) {
      folderDelete.disabled = false;
      showToast(error.message || '无法删除文件夹');
    }
    return;
  }
  const folderRename = event.target.closest('.rename-folder');
  if (folderRename) {
    openFolderRenameModal(folderRename.dataset.folderPath);
    return;
  }
  const folderMove = event.target.closest('.move-folder');
  if (folderMove) {
    openFolderMoveModal(folderMove.dataset.folderPath);
    return;
  }
  const folder = event.target.closest('.folder-open');
  if (folder) {
    currentDirectory = normalizeFolderPath(folder.dataset.folderPath);
    await loadFiles();
    return;
  }
  const rename = event.target.closest('.rename-file');
  if (rename) {
    openFileManageModal('rename', rename.dataset.id);
    return;
  }
  const move = event.target.closest('.move-file');
  if (move) {
    openFileManageModal('move', move.dataset.id);
    return;
  }
  const preview = event.target.closest('.preview-file');
  if (preview) {
    await openPreview(listedFiles.get(preview.dataset.id));
    return;
  }
  const download = event.target.closest('.download-file');
  if (download) {
    const item = listedFiles.get(download.dataset.id);
    await downloadEncryptedFile(item, download);
    return;
  }
  const button = event.target.closest('.delete-file');
  if (!button) return;
  const confirmed = await confirmAction({
    eyebrow: '删除文件',
    title: '永久删除此文件？',
    message: '“' + button.dataset.name + '”将从加密存储中永久删除，无法恢复。',
    confirmLabel: '永久删除'
  });
  if (!confirmed) return;
  button.disabled = true;
  try {
    await deleteFileIds([button.dataset.id]);
    showToast('文件已删除');
  } catch (error) {
    button.disabled = false;
    showToast(error.message);
  }
});

$('#remoteUploadList').addEventListener('click', async event => {
  const button = event.target.closest('.remote-cancel-upload');
  if (!button) return;
  const confirmed = await confirmAction({
    eyebrow: '删除临时上传',
    title: '删除未完成上传？',
    message: '该上传会话及所有临时加密分片将被删除，无法继续上传。',
    confirmLabel: '删除临时文件'
  });
  if (!confirmed) return;
  button.disabled = true;
  try {
    await api('/api/uploads/' + button.dataset.id, { method: 'DELETE' });
    me = await api('/api/me');
    updateStorage();
    await refreshRemoteUploads();
    showToast('临时加密分片已删除');
  } catch (error) {
    button.disabled = false;
    showToast(error.message);
  }
});

document.addEventListener('click', event => {
  const summary = event.target.closest('details.file-actions-mobile > summary');
  if (summary) {
    closeShareActionMenus(summary.parentElement);
    return;
  }
  if (!event.target.closest('details.file-actions-mobile')) {
    closeShareActionMenus();
  }
});

for (const eventName of ['pointerdown', 'touchstart']) {
  document.addEventListener(eventName, refreshVaultIdleTimer, { capture: true, passive: true });
}
document.addEventListener('keydown', refreshVaultIdleTimer, { capture: true });
document.addEventListener('keydown', event => {
  if (event.key !== 'Escape') return;
  const openActionMenu = document.querySelector('details.file-actions-mobile[open]');
  if (openActionMenu) closeShareActionMenus();
  else if (!$('#previewModal').hidden) requestClosePreviewModal();
  else if (!$('#createItemModal').hidden) closeCreateItemModal();
  else if (!$('#fileManageModal').hidden) closeFileManageModal();
});
window.addEventListener('pagehide', () => {
  clearTimeout(vaultIdleTimer);
  vaultIdleTimer = null;
  vaultKey = null;
  clearVaultPasskeyManagementMaterial();
  vaultPasskeyRemovalProof = '';
  accountDeletionPasskeyProof = '';
  pendingPasskeyRecommendation = false;
  closePreviewModal();
  clearPreviewChunkCache();
});
window.addEventListener('pageshow', event => {
  if (event.persisted) location.reload();
});


let yuniSharePollTimer = null;
function startYuniSharePolling() {
  if (yuniSharePollTimer) return;
  yuniSharePollTimer = setInterval(async () => {
    if (!me || document.hidden) return;
    if ($('#previewModal') && !$('#previewModal').hidden) return;
    if ($('#createItemModal') && !$('#createItemModal').hidden) return;
    if ($('#fileManageModal') && !$('#fileManageModal').hidden) return;
    if (selectedFileIds.size === 0 && (!selectedFolderPaths || selectedFolderPaths.size === 0)) {
      try {
        const response = await api('/api/me');
        me = response;
        updateStorage();
        await loadFiles();
      } catch {}
    }
  }, 5000);
}

setMode('login');
openSecureActionFromLocation();
loadSiteAnnouncement();
loadSession();
