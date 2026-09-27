const $ = selector => document.querySelector(selector);
const esc = value => String(value ?? '').replace(/[&<>"']/g, character => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[character]));
const fmt = value => value ? new Date(value).toLocaleString() : '-';
let activeAlertId = null;
let caseAlertId = null;

function requestHeaders(json = false) {
  const headers = {};
  const key = sessionStorage.getItem('siemApiKey');
  const analyst = sessionStorage.getItem('siemAnalyst') || 'analyst';
  if (key) headers['X-API-Key'] = key;
  headers['X-Analyst'] = analyst;
  if (json) headers['Content-Type'] = 'application/json';
  return headers;
}

async function api(path, options = {}) {
  options.headers = {...requestHeaders(Boolean(options.body)), ...(options.headers || {})};
  const response = await fetch(path, options);
  if (!response.ok) throw new Error((await response.text()) || `HTTP ${response.status}`);
  return response.json();
}

function toast(message, isError = false) {
  const element = $('#toast');
  element.textContent = message;
  element.className = isError ? 'show error' : 'show';
  setTimeout(() => { element.className = ''; }, 3000);
}

function setApiKey() {
  $('#credentials-analyst').value = sessionStorage.getItem('siemAnalyst') || 'analyst';
  $('#credentials-key').value = sessionStorage.getItem('siemApiKey') || '';
  $('#credentials-key').type = 'password';
  $('.reveal-button').textContent = 'Show';
  $('#credentials-dialog').showModal();
  setTimeout(() => $('#credentials-analyst').focus(), 0);
}

function toggleApiKey() {
  const input = $('#credentials-key');
  const showing = input.type === 'text';
  input.type = showing ? 'password' : 'text';
  $('.reveal-button').textContent = showing ? 'Show' : 'Hide';
}

function saveCredentials() {
  const analyst = $('#credentials-analyst').value.trim();
  const key = $('#credentials-key').value.trim();
  analyst ? sessionStorage.setItem('siemAnalyst', analyst) : sessionStorage.removeItem('siemAnalyst');
  key ? sessionStorage.setItem('siemApiKey', key) : sessionStorage.removeItem('siemApiKey');
  $('#credentials-dialog').close();
  toast('Session credentials saved');
}

function clearCredentials() {
  sessionStorage.removeItem('siemAnalyst');
  sessionStorage.removeItem('siemApiKey');
  $('#credentials-dialog').close();
  toast('Session credentials cleared');
}

async function loadStats() {
  const stats = await api('/api/stats');
  $('#total-events').textContent = stats.total_events;
  $('#events-24h').textContent = stats.events_24h;
  $('#open-alerts').textContent = stats.open_alerts;
  $('#open-cases').textContent = stats.open_cases;
  $('#critical-open').textContent = stats.critical_open;
  const entries = Object.entries(stats.events_by_source || {});
  const max = Math.max(1, ...entries.map(entry => entry[1]));
  $('#sources').innerHTML = entries.length
    ? entries.map(([source, count]) => `<div class="bar"><label><span>${esc(source)}</span><span>${count}</span></label><div class="track"><div class="fill" style="width:${Math.round(count / max * 100)}%"></div></div></div>`).join('')
    : '<p class="muted">No telemetry yet.</p>';
}

async function loadAlerts() {
  const severity = $('#alert-severity')?.value || '';
  const status = $('#alert-status')?.value || '';
  let path = '/api/alerts?limit=100';
  if (severity) path += `&severity=${encodeURIComponent(severity)}`;
  if (status) path += `&status=${encodeURIComponent(status)}`;
  const data = await api(path);
  $('#alerts-body').innerHTML = data.map(alert => `<tr class="clickable" onclick="openAlert(${alert.id})"><td>${fmt(alert.last_seen)}</td><td><span class="sev ${esc(alert.severity)}">${esc(alert.severity)}</span></td><td><strong>${esc(alert.title)}</strong><div class="muted">${esc(alert.rule_id)}</div></td><td>${esc(alert.mitre_technique || '-')}<div class="muted">${esc(alert.mitre_tactic || '')}</div></td><td>${alert.occurrence_count}</td><td>${esc(alert.assignee || 'Unassigned')}</td><td><span class="state">${esc(alert.status)}</span></td></tr>`).join('') || '<tr><td colspan="7" class="muted">No alerts.</td></tr>';
  const recent = data.slice(0, 6);
  $('#recent-alerts').innerHTML = recent.map(alert => `<button class="alertrow" onclick="openAlert(${alert.id})"><span class="sev ${esc(alert.severity)}">${esc(alert.severity)}</span><span><strong>${esc(alert.title)}</strong><small>${esc(alert.rule_id)} · ${esc(alert.mitre_technique || 'Unmapped')} · ${alert.occurrence_count} event(s)</small></span><small>${fmt(alert.last_seen)}</small></button>`).join('') || '<p class="muted">No alerts yet.</p>';
}

async function openAlert(id) {
  try {
    const alert = await api(`/api/alerts/${id}`);
    activeAlertId = id;
    $('#alert-rule').textContent = `${alert.rule_id} · ${alert.severity.toUpperCase()} · ${alert.occurrence_count} occurrence(s)`;
    $('#alert-title').textContent = alert.title;
    $('#detail-status').value = alert.status;
    $('#detail-assignee').value = alert.assignee || '';
    $('#detail-resolution').value = alert.resolution_reason || '';
    $('#alert-evidence').textContent = JSON.stringify(alert.evidence, null, 2);
    $('#alert-event').textContent = JSON.stringify(alert.event, null, 2);
    $('#alert-notes').innerHTML = alert.notes.length
      ? alert.notes.map(note => `<article class="note"><strong>${esc(note.author)}</strong><small>${fmt(note.created_at)}</small><p>${esc(note.body)}</p></article>`).join('')
      : '<p class="muted">No analyst notes yet.</p>';
    $('#alert-dialog').showModal();
  } catch (error) {
    toast(error.message, true);
  }
}

async function saveAlert() {
  if (!activeAlertId) return;
  try {
    await api(`/api/alerts/${activeAlertId}`, {
      method: 'PATCH',
      body: JSON.stringify({
        status: $('#detail-status').value,
        assignee: $('#detail-assignee').value || null,
        resolution_reason: $('#detail-resolution').value,
      }),
    });
    toast('Alert updated');
    await Promise.all([loadAlerts(), loadStats()]);
  } catch (error) {
    toast(error.message, true);
  }
}

async function addNote() {
  const body = $('#note-body').value.trim();
  if (!activeAlertId || !body) return;
  try {
    await api(`/api/alerts/${activeAlertId}/notes`, {
      method: 'POST',
      body: JSON.stringify({author: $('#note-author').value || 'analyst', body}),
    });
    $('#note-body').value = '';
    $('#alert-dialog').close();
    await openAlert(activeAlertId);
    toast('Note added');
  } catch (error) {
    toast(error.message, true);
  }
}

async function loadCases() {
  const cases = await api('/api/cases?limit=100');
  $('#cases-body').innerHTML = cases.map(item => `<tr><td>${fmt(item.updated_at)}</td><td><span class="sev ${esc(item.severity)}">${esc(item.severity)}</span></td><td><strong>${esc(item.title)}</strong><div class="muted">Case #${item.id}</div></td><td>${item.alert_count}</td><td>${esc(item.assignee || 'Unassigned')}</td><td><span class="state">${esc(item.status)}</span></td></tr>`).join('') || '<tr><td colspan="6" class="muted">No cases yet.</td></tr>';
}

function openNewCase(alertId = null) {
  caseAlertId = alertId;
  $('#case-dialog-title').textContent = alertId ? `Create case from alert #${alertId}` : 'New case';
  $('#case-title').value = '';
  $('#case-description').value = '';
  $('#case-assignee').value = sessionStorage.getItem('siemAnalyst') || '';
  $('#case-severity').value = 'medium';
  $('#case-dialog').showModal();
}

function caseFromAlert() {
  const id = activeAlertId;
  const title = $('#alert-title').textContent;
  const severity = $('#alert-rule').textContent.split(' · ')[1]?.toLowerCase() || 'medium';
  $('#alert-dialog').close();
  openNewCase(id);
  $('#case-title').value = `Investigation: ${title}`;
  if (['critical', 'high', 'medium', 'low', 'info'].includes(severity)) $('#case-severity').value = severity;
}

async function createCase() {
  const title = $('#case-title').value.trim();
  if (!title) return toast('A case title is required', true);
  try {
    await api('/api/cases', {
      method: 'POST',
      body: JSON.stringify({
        title,
        description: $('#case-description').value,
        severity: $('#case-severity').value,
        assignee: $('#case-assignee').value || null,
        alert_ids: caseAlertId ? [caseAlertId] : [],
      }),
    });
    $('#case-dialog').close();
    caseAlertId = null;
    toast('Investigation case created');
    await Promise.all([loadCases(), loadAlerts(), loadStats()]);
  } catch (error) {
    toast(error.message, true);
  }
}

async function loadEvents() {
  const source = $('#event-source')?.value || '';
  const query = $('#event-q')?.value || '';
  let path = '/api/events?limit=150';
  if (source) path += `&source=${encodeURIComponent(source)}`;
  if (query) path += `&q=${encodeURIComponent(query)}`;
  const data = await api(path);
  $('#events-body').innerHTML = data.map(event => `<tr><td>${fmt(event.timestamp)}</td><td>${esc(event.source)}</td><td>${esc(event.host)}</td><td>${esc(event.event_type)}</td><td>${esc(event.src_ip || '-')}</td><td>${esc(event.message).slice(0, 180)}</td></tr>`).join('') || '<tr><td colspan="6" class="muted">No events.</td></tr>';
}

async function loadRules() {
  const rules = await api('/api/rules');
  $('#rules-grid').innerHTML = Object.entries(rules).map(([id, rule]) => `<article><div class="rule-head"><h3>${esc(rule.title)}</h3><span class="enabled ${rule.enabled ? '' : 'off'}">${rule.enabled ? 'Enabled' : 'Disabled'}</span></div><span class="tag">${esc(id)}</span><span class="tag">${esc(rule.severity)}</span>${rule.mitre_technique ? `<span class="tag">${esc(rule.mitre_technique)}</span>` : ''}<p>${esc(rule.description)}</p><small class="muted">${esc(rule.mitre_tactic || '')}${rule.threshold ? ` · threshold ${rule.threshold}/${rule.window_seconds}s` : ''}</small></article>`).join('');
}

document.querySelectorAll('.nav').forEach(button => button.addEventListener('click', () => {
  document.querySelectorAll('.nav,.tab').forEach(element => element.classList.remove('active'));
  button.classList.add('active');
  $(`#${button.dataset.tab}`).classList.add('active');
  $('#page-title').textContent = {overview:'Security Overview', alerts:'Alert Queue', cases:'Investigation Cases', events:'Security Events', rules:'Detection Rules'}[button.dataset.tab];
}));

async function refresh() {
  try {
    await Promise.all([loadStats(), loadAlerts(), loadCases(), loadEvents(), loadRules()]);
  } catch (error) {
    console.error(error);
    toast('Could not load SIEM data', true);
  }
}

refresh();
setInterval(async () => {
  try { await Promise.all([loadStats(), loadAlerts()]); } catch (error) { console.error(error); }
}, 5000);
