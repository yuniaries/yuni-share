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

let selectedUser = null;
let loadedUsers = [];
let toastTimer = null;
let auditPage = 1;
let auditTotalPages = 1;
let userPage = 1;
let userTotalPages = 1;
let userTotal = 0;
let userPageSize = 20;
let globalAuditPage = 1;
let globalAuditTotalPages = 1;
let activeModule = 'overview';
let loadedContent = [];
let selectedContentKey = 'terms';

const bytes = value => `${(Number(value) / 1024 ** 3).toFixed(Number(value) % (1024 ** 3) ? 1 : 0)} GB`;
const date = value => value ? new Date(Number(value)).toLocaleString('zh-CN') : '—';
const moduleNames = { overview: '控制总览', users: '用户与配额', content: '条款与公告', audit: '审计记录' };
const contentRoutes = { terms: '/terms', 'user-agreement': '/user-agreement', privacy: '/privacy', disclaimer: '/disclaimer' };

async function api(url, options) {
  const response = await fetch(url, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || '请求失败');
  return data;
}

function escape(value) {
  const node = document.createElement('span');
  node.textContent = String(value ?? '');
  return node.innerHTML;
}

function initials(value) {
  return String(value || 'Y').replace(/[^a-z0-9]/ig, '').slice(0, 2).toUpperCase() || 'Y';
}

function toast(message) {
  const node = $('#toast');
  node.textContent = message;
  node.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { node.hidden = true; }, 3600);
}

function showModule(module) {
  if (!moduleNames[module]) return;
  activeModule = module;
  document.querySelectorAll('.module-panel').forEach(panel => { panel.hidden = panel.id !== module + 'Module'; });
  document.querySelectorAll('#moduleNav [data-module]').forEach(button => button.classList.toggle('active', button.dataset.module === module));
  $('#moduleTitle').textContent = moduleNames[module];
  if (module === 'overview') loadOverview().catch(error => toast(error.message));
  if (module === 'users') loadUsers(1);
  if (module === 'content') loadContent().catch(error => toast(error.message));
  if (module === 'audit') loadGlobalAudit().catch(error => toast(error.message));
}

function formatCount(value) {
  return new Intl.NumberFormat('zh-CN').format(Number(value) || 0);
}

function renderOverviewStats(stats) {
  const cards = [
    ['账户', formatCount(stats.users), '注册用户'],
    ['加密文件', formatCount(stats.files), '已完成对象'],
    ['逻辑用量', bytes(stats.usedBytes), '用户原始文件大小'],
    ['临时上传', formatCount(stats.uploads), '等待完成或清理'],
    ['有效会员', formatCount(stats.activeMemberships), '当前有效订阅'],
    ['删除计划', formatCount(stats.scheduledDeletions), '等待恢复期结束']
  ];
  setTrustedHtml($('#overviewStats'), cards.map(card => `<article class="statcard"><span>${escape(card[0])}</span><strong>${escape(card[1])}</strong><small>${escape(card[2])}</small></article>`).join(''));
}

function renderSystemStatus(data) {
  const storageLabel = data.storage?.ok ? 'Storage 正常' : data.storage?.configured ? 'Storage 检查失败' : '未配置 Storage';
  const storageClass = data.storage?.ok ? 'ok' : 'warn';
  setTrustedHtml($('#systemStatus'), `<div class="systemrow"><span>Share API</span><b class="statusdot ok">运行中</b></div><div class="systemrow"><span>端到端加密存储</span><b class="statusdot ${storageClass}">${escape(storageLabel)}</b></div><div class="systemrow"><span>服务端密钥</span><b class="statusdot ok">不接触文件密钥</b></div><div class="systemrow"><span>内容版本控制</span><b class="statusdot ok">已启用</b></div>`);
  $('#systemStatusBadge').textContent = data.storage?.ok ? '全部正常' : '需要关注';
  $('#systemStatusBadge').classList.toggle('status-warning', !data.storage?.ok);
}

function auditActionLabel(action) {
  return action === 'quota_adjusted' ? '调整配额'
    : action === 'refund_revoked_membership' ? '撤销会员'
      : action === 'site_content_updated' ? '发布内容'
        : action === 'site_content_restored' ? '恢复内容版本'
          : action === 'site_content_unpublished' ? '撤销发布' : '管理员操作';
}

function renderRecentActivity(entries) {
  setTrustedHtml($('#recentActivity'), entries.length ? entries.map(entry => `<article class="recentrow"><div><strong>${escape(auditActionLabel(entry.action))}</strong><small>${escape(entry.username || (Number(entry.target_user_id) ? `用户 #${entry.target_user_id}` : '全局设置'))}</small></div><time>${escape(date(entry.created_at))}</time></article>`).join('') : '<p class="emptycopy">暂无操作记录。</p>');
}

async function loadOverview() {
  const data = await api('/api/admin/dashboard');
  renderOverviewStats(data.stats);
  renderSystemStatus(data);
  renderRecentActivity(data.recentAudit);
}

function openModal(node) {
  node.hidden = false;
  node.classList.add('is-open');
}

function closeModal(node) {
  node.classList.remove('is-open');
  node.hidden = true;
}

function hasActiveMembership(user) {
  return Number(user?.membership_active) === 1 && Number(user?.expires_at) > Date.now();
}

function membershipLabel(user) {
  if (hasActiveMembership(user)) return `${String(user.plan_id).toUpperCase()} · 有效`;
  if (user.plan_id) return `${String(user.plan_id).toUpperCase()} · 已过期`;
  return '免费版';
}

function addonName(addon) {
  const names = {
    storage_50: '50 GB 叠加包',
    storage_200: '200 GB 叠加包',
    storage_500: '500 GB 叠加包',
    storage_1024: '1 TB 叠加包'
  };
  return names[addon?.addon_id] || `${bytes(addon?.quota_bytes || 0)} 叠加包`;
}

function activeAddons(user) {
  return Array.isArray(user?.storage_addons) ? user.storage_addons : [];
}

async function loadUsers(page = 1) {
  $('#status').textContent = '正在读取用户…';
  try {
    const status = $('#userStatusFilter').value;
    const data = await api(`/api/admin/users?search=${encodeURIComponent($('#search').value.trim())}&status=${encodeURIComponent(status)}&page=${encodeURIComponent(page)}`);
    loadedUsers = data.users;
    userPage = data.page;
    userTotalPages = data.totalPages;
    userTotal = data.total;
    userPageSize = data.pageSize;
    $('#status').textContent = `找到 ${formatCount(data.total)} 位用户 · 当前第 ${data.page} / ${data.totalPages} 页`;
    setTrustedHtml($('#users'), data.users.length
      ? data.users.map(user => `<button class="user${user.deletion_status === 'scheduled' ? ' user-pending-deletion' : ''}" data-id="${user.id}">
          <strong>${escape(user.username)}</strong>
          <span>${escape(user.email || '未设置邮箱')}</span>
          <span class="userentitlements"><b>${bytes(user.used_bytes)} / ${bytes(user.quota_bytes)} · ${escape(membershipLabel(user))}</b>${Number(user.addon_count) > 0 ? `<small>${user.addon_count} 个叠加包 · +${bytes(user.addon_quota_bytes)}</small>` : '<small>未购买有效叠加包</small>'}${user.deletion_status === 'scheduled' ? `<small class="userdeletion">待删除 · 恢复截止 ${escape(date(user.deletion_scheduled_for))}</small>` : ''}</span>
        </button>`).join('')
      : '<p>没有匹配的用户。</p>');
    $('#userPageInfo').textContent = `第 ${data.page} / ${data.totalPages} 页 · 每页 ${data.pageSize} 位`;
    $('#userPrev').disabled = data.page <= 1;
    $('#userNext').disabled = data.page >= data.totalPages;
  } catch (error) {
    $('#status').textContent = error.message;
  }
}

function auditTitle(action) {
  return action === 'quota_adjusted' ? '存储配额已调整'
    : action === 'refund_revoked_membership' ? '会员退款并撤销'
      : action === 'site_content_updated' ? '站点内容已发布'
        : action === 'site_content_restored' ? '站点内容已恢复历史版本'
          : action === 'site_content_unpublished' ? '站点公告已撤销发布'
      : '管理员操作';
}

function detailRow(label, value) {
  return `<div><dt>${escape(label)}</dt><dd>${escape(value)}</dd></div>`;
}

function readableAuditDetails(entry) {
  const details = entry.details || {};
  if (entry.action === 'quota_adjusted') {
    return [
      detailRow('原配额', bytes(details.previousQuotaBytes || 0)),
      detailRow('新配额', bytes(details.quotaBytes || 0)),
      detailRow('调整原因', details.reason || '未填写')
    ].join('');
  }
  if (entry.action === 'refund_revoked_membership') {
    const membership = details.previousSubscription;
    const addons = Array.isArray(details.previousStorageAddons)
      ? details.previousStorageAddons
      : details.previousStorageAddon ? [details.previousStorageAddon] : [];
    const addonQuota = addons.reduce((sum, addon) => sum + Number(addon?.quota_bytes || 0), 0);
    return [
      detailRow('原会员', membership?.plan_id ? String(membership.plan_id).toUpperCase() : '旧记录未保存会员信息'),
      detailRow('原会员配额', membership?.quota_bytes ? bytes(membership.quota_bytes) : '—'),
      detailRow('原到期时间', membership?.expires_at ? date(membership.expires_at) : '—'),
      detailRow('已撤销叠加包', addons.length ? `${addons.length} 个 · ${bytes(addonQuota)}` : '无'),
      detailRow('叠加包明细', addons.length ? addons.map(addon => `${addonName(addon)}（至 ${date(addon.expires_at)}）`).join('；') : '—'),
      detailRow('恢复配额', bytes(details.restoredQuotaBytes || 0)),
      detailRow('退款说明', details.reason || '未填写')
    ].join('');
  }
  const rows = Object.entries(details).map(([key, value]) => detailRow(key, typeof value === 'object' ? '相关信息已记录' : value));
  return rows.length ? rows.join('') : detailRow('详情', '无附加说明');
}

function auditMarkup(entries) {
  return entries.length
    ? entries.map(entry => `<article class="audit">
        <div class="auditidentity"><strong>${escape(auditTitle(entry.action))}</strong><span>${date(entry.created_at)}</span><small>${escape(entry.username || (Number(entry.target_user_id) ? `已删除用户 #${entry.target_user_id}` : '全局设置'))}${entry.email ? ` · ${escape(entry.email)}` : ''}</small></div>
        <dl class="auditdetails">${readableAuditDetails(entry)}</dl>
      </article>`).join('')
    : '<p class="emptycopy">尚无管理员操作记录。</p>';
}

function renderAudit(entries) {
  setTrustedHtml($('#audit'), auditMarkup(entries));
}

function renderGlobalAudit(entries) {
  setTrustedHtml($('#globalAudit'), auditMarkup(entries));
}

async function loadAudit(page = 1) {
  const search = $('#auditSearch').value.trim();
  const data = await api(`/api/admin/audit?search=${encodeURIComponent(search)}&page=${encodeURIComponent(page)}`);
  auditPage = data.page;
  auditTotalPages = data.totalPages;
  renderAudit(data.audit);
  $('#auditCount').textContent = `共 ${data.total} 条 · 每页 ${data.pageSize} 条`;
  $('#auditPageInfo').textContent = `第 ${data.page} / ${data.totalPages} 页`;
  $('#auditPrev').disabled = data.page <= 1;
  $('#auditNext').disabled = data.page >= data.totalPages;
}

async function loadGlobalAudit(page = 1) {
  const search = $('#globalAuditSearch').value.trim();
  const data = await api(`/api/admin/audit?search=${encodeURIComponent(search)}&page=${encodeURIComponent(page)}`);
  globalAuditPage = data.page;
  globalAuditTotalPages = data.totalPages;
  renderGlobalAudit(data.audit);
  $('#globalAuditCount').textContent = `共 ${data.total} 条 · 每页 ${data.pageSize} 条`;
  $('#globalAuditPageInfo').textContent = `第 ${data.page} / ${data.totalPages} 页`;
  $('#globalAuditPrev').disabled = data.page <= 1;
  $('#globalAuditNext').disabled = data.page >= data.totalPages;
}

function renderContentPreview(content) {
  const title = $('#contentTitle').value.trim() || content?.title || '页面标题';
  const intro = $('#contentIntro').value.trim() || content?.intro || '';
  const meta = $('#contentMeta').value.trim() || content?.meta || '';
  const body = $('#contentEditor').innerHTML || content?.bodyHtml || '<p>开始编辑正文。</p>';
  setTrustedHtml($('#contentPreview'), `<p class="eyebrow">YUNI SHARE</p><h2>${escape(title)}</h2><p class="previewintro">${escape(intro)}</p><p class="previewmeta">${escape(meta)}</p><div class="previewbody">${body}</div>`);
}

function renderContentTabs() {
  setTrustedHtml($('#contentTabs'), loadedContent.map(content => `<button type="button" class="contenttab${content.key === selectedContentKey ? ' active' : ''}" data-content-key="${escape(content.key)}"><strong>${escape(content.label)}</strong><small>${content.enabled ? '已发布' : '未发布'}</small></button>`).join(''));
}

function renderRevisions(revisions) {
  setTrustedHtml($('#contentRevisions'), revisions.length ? revisions.map(revision => `<article class="revisionrow"><div><strong>${escape(revision.title)}</strong><small>${escape(date(revision.createdAt))} · 历史快照</small></div><button type="button" class="secondary" data-restore-revision="${revision.id}">恢复此版本</button></article>`).join('') : '<p class="emptycopy">保存后会在这里显示历史版本。</p>');
}

async function loadRevisions(key) {
  const data = await api(`/api/admin/site-content/${encodeURIComponent(key)}/revisions`);
  renderRevisions(data.revisions);
}

function selectContent(key) {
  const content = loadedContent.find(item => item.key === key);
  if (!content) return;
  selectedContentKey = key;
  $('#contentTitle').value = content.title;
  $('#contentIntro').value = content.intro;
  $('#contentMeta').value = content.meta;
  setTrustedHtml($('#contentEditor'), content.bodyHtml || '<p></p>');
  $('#announcementEnabledField').hidden = key !== 'announcement';
  $('#announcementEnabled').checked = Boolean(content.enabled);
  $('#openContentPage').hidden = !contentRoutes[key];
  $('#openContentPage').href = contentRoutes[key] || '/';
  $('#unpublishContent').hidden = !(key === 'announcement' && content.enabled);
  $('#contentStatus').textContent = content.enabled ? `已发布 · ${date(content.updatedAt)}` : '未发布';
  renderContentTabs();
  renderContentPreview(content);
  loadRevisions(key).catch(error => toast(error.message));
}

async function loadContent() {
  const data = await api('/api/admin/site-content');
  loadedContent = data.content;
  if (!loadedContent.some(item => item.key === selectedContentKey)) selectedContentKey = loadedContent[0]?.key || 'terms';
  selectContent(selectedContentKey);
}

function runEditorCommand(button) {
  const command = button.dataset.command;
  if (command === 'createLink') {
    const href = window.prompt('输入安全链接（https://、mailto: 或站内 / 路径）', 'https://');
    if (!href) return;
    document.execCommand('createLink', false, href.trim());
  } else {
    document.execCommand(command, false, button.dataset.value || null);
  }
  $('#contentEditor').focus();
  renderContentPreview();
}

async function saveContent(event) {
  event.preventDefault();
  const button = $('#saveContent');
  button.disabled = true;
  try {
    const data = await api(`/api/admin/site-content/${encodeURIComponent(selectedContentKey)}`, {
      method: 'PUT', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ title: $('#contentTitle').value, intro: $('#contentIntro').value, meta: $('#contentMeta').value, bodyHtml: $('#contentEditor').innerHTML, enabled: $('#announcementEnabled').checked })
    });
    const index = loadedContent.findIndex(item => item.key === selectedContentKey);
    if (index >= 0) loadedContent[index] = data.content;
    selectContent(selectedContentKey);
    toast(data.unchanged ? '内容没有变化。' : '内容已保存并发布。');
  } catch (error) {
    toast(error.message);
  } finally {
    button.disabled = false;
  }
}

async function unpublishContent() {
  if (selectedContentKey !== 'announcement') return;
  if (!window.confirm('撤销公告发布？公告将从首页隐藏，但正文和历史版本会保留。')) return;
  const button = $('#unpublishContent');
  button.disabled = true;
  try {
    const data = await api('/api/admin/site-content/announcement/unpublish', { method: 'POST' });
    const index = loadedContent.findIndex(item => item.key === 'announcement');
    if (index >= 0) loadedContent[index] = data.content;
    selectContent('announcement');
    toast(data.unchanged ? '公告本来就是未发布状态。' : '公告已撤销发布。');
  } catch (error) {
    toast(error.message);
  } finally {
    button.disabled = false;
  }
}

async function restoreRevision(id) {
  if (!window.confirm('恢复此历史版本？当前内容会先自动保存为新的历史版本。')) return;
  try {
    const data = await api(`/api/admin/site-content/${encodeURIComponent(selectedContentKey)}/revisions/${encodeURIComponent(id)}/restore`, { method: 'POST' });
    const index = loadedContent.findIndex(item => item.key === selectedContentKey);
    if (index >= 0) loadedContent[index] = data.content;
    selectContent(selectedContentKey);
    toast('历史版本已恢复并发布。');
  } catch (error) {
    toast(error.message);
  }
}

function updateRefundAvailability(user) {
  const active = hasActiveMembership(user);
  const form = $('#refundForm');
  const reason = $('#refundReason');
  const button = $('#refundButton');
  form.classList.toggle('inactive', !active);
  reason.disabled = !active;
  button.disabled = !active;
  $('#refundEligibility').classList.toggle('membership-inactive', !active);
  if (active) {
    const addons = activeAddons(user);
    const addonNote = addons.length ? `，同时撤销 ${addons.length} 个叠加包（共 ${bytes(user.addon_quota_bytes)}）` : '';
    setTrustedHtml($('#refundEligibility'), `当前 <strong>${escape(String(user.plan_id).toUpperCase())}</strong> 会员有效至 ${escape(date(user.expires_at))}。退款后会员将被撤销${escape(addonNote)}，账户配额恢复为 <strong>5 GB</strong>，并发送邮件通知。`);
    button.textContent = '继续退款操作';
  } else {
    $('#refundEligibility').textContent = user.plan_id
      ? '该用户的会员已经过期，不能执行会员退款。'
      : '该用户当前没有有效会员，不能执行会员退款。';
    button.textContent = '无有效会员，无法退款';
  }
}

async function showUser(id) {
  const user = loadedUsers.find(item => item.id === Number(id));
  if (!user) return;
  selectedUser = user;
  $('#detail').hidden = false;
  $('#userInitial').textContent = initials(user.username);
  $('#detailTitle').textContent = `${user.username} · #${user.id}`;
  $('#detailMeta').textContent = user.email || '未设置邮箱';
  const pendingDeletion = user.deletion_status === 'scheduled';
  $('#deletionStatus').hidden = !pendingDeletion;
  $('#deletionStatus').textContent = pendingDeletion
    ? `待删除账户 · ${date(user.deletion_scheduled_for)} 执行删除 · ${user.deletion_retention_days || '—'} 天恢复期`
    : '';
  const addons = activeAddons(user);
  setTrustedHtml($('#statGrid'), `<div class="stat"><span>已用空间</span><strong>${bytes(user.used_bytes)}</strong></div>
    <div class="stat"><span>总配额</span><strong>${bytes(user.quota_bytes)}</strong></div>
    <div class="stat"><span>叠加空间</span><strong>${addons.length ? `+${bytes(user.addon_quota_bytes)}` : '无'}</strong></div>
    <div class="stat"><span>会员状态</span><strong>${escape(membershipLabel(user))}${hasActiveMembership(user) ? ` · 至 ${escape(date(user.expires_at))}` : ''}</strong></div>`);
  setTrustedHtml($('#addonInventory'), `<div class="addoninventoryhead"><div><span>STORAGE ADD-ONS</span><h3>已购叠加包</h3></div><b>${addons.length} 个有效</b></div>${addons.length
    ? `<div class="addonrows">${addons.map(addon => `<article><div><strong>${escape(addonName(addon))}</strong><small>购买于 ${escape(date(addon.created_at))}</small></div><b>+${bytes(addon.quota_bytes)}</b><span>有效至 ${escape(date(addon.expires_at))}</span></article>`).join('')}</div>`
    : '<p class="addonempty">该用户当前没有有效叠加包。</p>'}`);
  $('#quotaGb').value = Math.round(user.quota_bytes / 1024 ** 3);
  updateRefundAvailability(user);
  $('#auditSearch').value = user.email || user.username;
  await loadAudit(1);
}

async function boot() {
  try {
    await api('/api/admin/session');
    $('#loginView').hidden = true;
    $('#adminView').hidden = false;
    showModule('overview');
  } catch {}
}

$('#loginForm').addEventListener('submit', async event => {
  event.preventDefault();
  $('#loginError').textContent = '';
  try {
    await api('/api/admin/login', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username: $('#username').value, password: $('#password').value })
    });
    $('#loginView').hidden = true;
    $('#adminView').hidden = false;
    showModule('overview');
  } catch (error) {
    $('#loginError').textContent = error.message;
  }
});

$('#logout').onclick = async () => {
  await api('/api/admin/logout', { method: 'POST' });
  location.reload();
};

$('#moduleNav').onclick = event => {
  const button = event.target.closest('[data-module]');
  if (button) showModule(button.dataset.module);
};
document.querySelectorAll('[data-module-link]').forEach(button => {
  button.addEventListener('click', () => showModule(button.dataset.moduleLink));
});
$('#refreshOverview').onclick = () => loadOverview().catch(error => toast(error.message));

$('#contentTabs').onclick = event => {
  const button = event.target.closest('[data-content-key]');
  if (button) selectContent(button.dataset.contentKey);
};
$('#contentForm').addEventListener('submit', saveContent);
['#contentTitle', '#contentIntro', '#contentMeta', '#contentEditor'].forEach(selector => $(selector).addEventListener('input', () => renderContentPreview()));
$('#editorToolbar').onclick = event => {
  const button = event.target.closest('[data-command]');
  if (button) runEditorCommand(button);
};
$('#contentRevisions').onclick = event => {
  const button = event.target.closest('[data-restore-revision]');
  if (button) restoreRevision(button.dataset.restoreRevision);
};
$('#unpublishContent').onclick = unpublishContent;
$('#globalAuditSearchForm').addEventListener('submit', event => {
  event.preventDefault();
  loadGlobalAudit(1).catch(error => toast(error.message));
});
$('#globalAuditPrev').onclick = () => loadGlobalAudit(Math.max(1, globalAuditPage - 1)).catch(error => toast(error.message));
$('#globalAuditNext').onclick = () => loadGlobalAudit(Math.min(globalAuditTotalPages, globalAuditPage + 1)).catch(error => toast(error.message));

$('#searchButton').onclick = loadUsers;
$('#search').addEventListener('keydown', event => { if (event.key === 'Enter') loadUsers(); });
$('#userStatusFilter').addEventListener('change', () => loadUsers(1));
$('#userPrev').onclick = () => loadUsers(Math.max(1, userPage - 1)).catch(error => toast(error.message));
$('#userNext').onclick = () => loadUsers(Math.min(userTotalPages, userPage + 1)).catch(error => toast(error.message));
$('#auditSearchForm').addEventListener('submit', event => {
  event.preventDefault();
  loadAudit(1).catch(error => toast(error.message));
});
$('#auditPrev').onclick = () => loadAudit(Math.max(1, auditPage - 1)).catch(error => toast(error.message));
$('#auditNext').onclick = () => loadAudit(Math.min(auditTotalPages, auditPage + 1)).catch(error => toast(error.message));
$('#users').onclick = event => {
  const id = event.target.closest('[data-id]')?.dataset.id;
  if (id) showUser(id).catch(error => toast(error.message));
};
$('#closeDetail').onclick = () => { $('#detail').hidden = true; selectedUser = null; };

$('#quotaForm').addEventListener('submit', async event => {
  event.preventDefault();
  if (!selectedUser) return;
  const userId = selectedUser.id;
  try {
    await api(`/api/admin/users/${userId}/quota`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ quotaBytes: Math.round(Number($('#quotaGb').value) * 1024 ** 3), reason: $('#quotaReason').value })
    });
    await loadUsers(userPage);
    await showUser(userId);
    toast('配额已更新，邮件通知已排队。');
  } catch (error) {
    toast(error.message);
  }
});

function closeRefundConfirm() {
  closeModal($('#confirmModal'));
  $('#confirmCheck').checked = false;
  $('#approveConfirm').disabled = true;
}

$('#refundForm').addEventListener('submit', event => {
  event.preventDefault();
  if (!selectedUser || !hasActiveMembership(selectedUser)) {
    toast('该用户当前没有有效会员，无法退款。');
    return;
  }
  $('#confirmUserInitial').textContent = initials(selectedUser.username);
  $('#confirmUser').textContent = `${selectedUser.username} · #${selectedUser.id}`;
  const addons = activeAddons(selectedUser);
  $('#confirmPlan').textContent = `当前会员：${String(selectedUser.plan_id).toUpperCase()} · 到期：${date(selectedUser.expires_at)}${addons.length ? ` · 同时撤销 ${addons.length} 个叠加包` : ''}`;
  openModal($('#confirmModal'));
});

$('#confirmCheck').onchange = event => { $('#approveConfirm').disabled = !event.target.checked; };
$('#cancelConfirm').onclick = closeRefundConfirm;
$('#cancelConfirmX').onclick = closeRefundConfirm;
$('#confirmModal').onclick = event => { if (event.target === $('#confirmModal')) closeRefundConfirm(); };

$('#approveConfirm').onclick = async () => {
  if (!selectedUser || !hasActiveMembership(selectedUser)) return;
  const userId = selectedUser.id;
  const button = $('#approveConfirm');
  button.disabled = true;
  button.textContent = '正在处理…';
  try {
    await api(`/api/admin/users/${userId}/refund-revoke-membership`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ reason: $('#refundReason').value })
    });
    closeRefundConfirm();
    await loadUsers(userPage);
    await showUser(userId);
    toast('会员已撤销，5 GB 配额与邮件通知已处理。');
  } catch (error) {
    closeRefundConfirm();
    await loadUsers(userPage);
    await showUser(userId).catch(() => undefined);
    toast(error.message);
  } finally {
    button.textContent = '确认退款并撤销会员';
  }
};

function closePasskeyManager() {
  closeModal($('#passkeyManagerModal'));
}

function shortCredential(value) {
  const text = String(value || '');
  return text.length > 20 ? `${text.slice(0, 10)}…${text.slice(-8)}` : text;
}

function transportLabel(items) {
  const labels = { internal: '本机验证器', hybrid: '跨设备', usb: 'USB 安全密钥', nfc: 'NFC', ble: '蓝牙' };
  return (items || []).map(item => labels[item] || item).join('、') || '由密码管理器保存';
}

async function loadAdminPasskeys() {
  setTrustedHtml($('#passkeyList'), '<p>正在读取 Passkey…</p>');
  const data = await api('/api/admin/passkeys');
  setTrustedHtml($('#passkeyList'), data.passkeys.length
    ? data.passkeys.map((passkey, index) => `<article class="passkeyrow">
        <div><strong>Passkey ${index + 1}</strong><small>${escape(shortCredential(passkey.credentialId))}<br>保存方式：${escape(transportLabel(passkey.transports))}<br>添加：${escape(date(passkey.createdAt))} · 最近使用：${escape(date(passkey.lastUsedAt))}</small></div>
        <button type="button" class="passkeydelete" data-delete-passkey="${escape(passkey.credentialId)}">删除</button>
      </article>`).join('')
    : '<p class="emptycopy">尚未添加管理员 Passkey。你仍可使用管理员密码登录。</p>');
}

async function openPasskeyManager() {
  openModal($('#passkeyManagerModal'));
  try { await loadAdminPasskeys(); } catch (error) { $('#passkeyList').textContent = error.message; }
}

$('#managePasskeys').onclick = openPasskeyManager;
$('#closePasskeyManager').onclick = closePasskeyManager;
$('#closePasskeyManagerX').onclick = closePasskeyManager;
$('#passkeyManagerModal').onclick = event => { if (event.target === $('#passkeyManagerModal')) closePasskeyManager(); };

$('#passkeyList').onclick = async event => {
  const button = event.target.closest('[data-delete-passkey]');
  if (!button) return;
  if (button.dataset.confirming !== 'true') {
    $('#passkeyList').querySelectorAll('[data-delete-passkey]').forEach(item => {
      item.dataset.confirming = 'false'; item.classList.remove('confirming'); item.textContent = '删除';
    });
    button.dataset.confirming = 'true';
    button.classList.add('confirming');
    button.textContent = '再次点击确认';
    setTimeout(() => {
      if (!button.isConnected || button.dataset.confirming !== 'true') return;
      button.dataset.confirming = 'false'; button.classList.remove('confirming'); button.textContent = '删除';
    }, 5000);
    return;
  }
  button.disabled = true;
  try {
    await api(`/api/admin/passkeys/${encodeURIComponent(button.dataset.deletePasskey)}`, { method: 'DELETE' });
    toast('管理员 Passkey 已删除。');
    await loadAdminPasskeys();
  } catch (error) {
    button.disabled = false;
    toast(error.message);
  }
};

function b64urlToBytes(value) {
  const padded = String(value).replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((String(value).length + 3) % 4);
  return Uint8Array.from(atob(padded), character => character.charCodeAt(0));
}

function bytesToB64url(value) {
  let binary = '';
  for (const byte of new Uint8Array(value)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function browserRegistrationOptions(options) {
  return { ...options, challenge: b64urlToBytes(options.challenge), user: { ...options.user, id: b64urlToBytes(options.user.id) }, excludeCredentials: options.excludeCredentials?.map(item => ({ ...item, id: b64urlToBytes(item.id) })) };
}

function browserAuthenticationOptions(options) {
  return { ...options, challenge: b64urlToBytes(options.challenge), allowCredentials: options.allowCredentials?.map(item => ({ ...item, id: b64urlToBytes(item.id) })) };
}

function passkeyResponse(credential) {
  const response = credential.response;
  const base = { id: credential.id, rawId: bytesToB64url(credential.rawId), type: credential.type, authenticatorAttachment: credential.authenticatorAttachment || undefined, clientExtensionResults: credential.getClientExtensionResults?.() || {} };
  return typeof response.getTransports === 'function'
    ? { ...base, response: { clientDataJSON: bytesToB64url(response.clientDataJSON), attestationObject: bytesToB64url(response.attestationObject), transports: response.getTransports() } }
    : { ...base, response: { clientDataJSON: bytesToB64url(response.clientDataJSON), authenticatorData: bytesToB64url(response.authenticatorData), signature: bytesToB64url(response.signature), ...(response.userHandle ? { userHandle: bytesToB64url(response.userHandle) } : {}) } };
}

function passkeyAvailable() {
  return Boolean(window.isSecureContext && window.PublicKeyCredential && navigator.credentials?.create && navigator.credentials?.get);
}

async function loginWithPasskey() {
  if (!passkeyAvailable()) return toast('当前浏览器或连接不支持 Passkey。请使用 HTTPS 和最新版浏览器。');
  try {
    const start = await api('/api/admin/passkey-login/options', { method: 'POST' });
    const credential = await navigator.credentials.get({ publicKey: browserAuthenticationOptions(start.options) });
    if (!credential) throw new Error('未返回 Passkey 凭据');
    await api('/api/admin/passkey-login/verify', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ challengeId: start.challengeId, response: passkeyResponse(credential) }) });
    $('#loginView').hidden = true;
    $('#adminView').hidden = false;
    showModule('overview');
  } catch (error) {
    toast(error.name === 'NotAllowedError' ? 'Passkey 操作已取消或超时。' : error.message);
  }
}

async function registerAdminPasskey() {
  if (!passkeyAvailable()) return toast('当前浏览器或连接不支持 Passkey。请使用 HTTPS 和最新版浏览器。');
  const button = $('#registerPasskey');
  button.disabled = true;
  try {
    const start = await api('/api/admin/passkeys/registration/options', { method: 'POST' });
    const credential = await navigator.credentials.create({ publicKey: browserRegistrationOptions(start.options) });
    if (!credential) throw new Error('未返回 Passkey 凭据');
    await api('/api/admin/passkeys/registration/verify', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ challengeId: start.challengeId, response: passkeyResponse(credential) }) });
    toast('管理员 Passkey 已添加，可用于下次登录。');
    await loadAdminPasskeys();
  } catch (error) {
    toast(error.name === 'NotAllowedError' ? 'Passkey 操作已取消或超时。' : error.message);
  } finally {
    button.disabled = false;
  }
}

$('#passkeyLogin').onclick = loginWithPasskey;
$('#registerPasskey').onclick = registerAdminPasskey;

boot();
