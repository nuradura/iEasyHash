I18n.ready.then(() => {
const {t, locale} = I18n;
'use strict';

const $ = s => document.querySelector(s),
  $$ = s => [...document.querySelectorAll(s)];
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;'
})[c]);
const csrf = $('meta[name=csrf-token]').content;
let state = {
    hashes: [],
    wordlists: [],
    jobs: [],
    attempts: [],
    worker_online: false,
    total_jobs: 0
  },
  system = null,
  page = 'dashboard',
  busy = false,
  refreshing = false;
let temps = [],
  githubStamp = '',
  modalReturnFocus = null;
const titles = {
  dashboard: [t("Overview"), t("Under control."), t("Audit the password strength of your own Wi-Fi networks."), t("NETWORK SECURITY / OVERVIEW")],
  networks: [t("My networks"), t("Your networks."), t("Your captures, results and recovery history."), t("NETWORK SECURITY / CAPTURES")],
  wordlists: [t("Dictionaries"), t("Words matter."), t("Build your library and arrange the audit order."), t("NETWORK SECURITY / WORDLISTS")],
  history: [t("History"), t("Every pass, recorded."), t("Completed jobs, recovered passwords and engine logs."), t("NETWORK SECURITY / HISTORY")],
  system: [t("Server"), t("Server compute."), t("GTX 1070, worker and audit tool status."), t("NETWORK SECURITY / COMPUTE")]
};
const names = {
  queued: t("Queued"),
  running: t("Running"),
  pausing: t("Pausing\u2026"),
  stopping: t("Stopping\u2026"),
  paused: t("Paused"),
  completed: t("Completed"),
  stopped: t("Stopped"),
  failed: t("Failed"),
  interrupted: t("Interrupted"),
  recovered: t("Recovered"),
  exhausted: t("No match"),
  skipped: t("Skipped"),
  no_match: t("No match"),
  found: t("Recovered"),
  neutral: t("Not tested")
};
const badge = status => `<span class="badge ${esc(status)}">${esc(names[status] || status)}</span>`;
const bytes = n => {
  if (!n) return t("0 B");
  const units = [t("B"), t("KB"), t("MB"), t("GB"), t("TB")];
  const i = Math.min(4, Math.floor(Math.log(n) / Math.log(1024)));
  return `${(n / 1024 ** i).toLocaleString(locale, {
    maximumFractionDigits: i ? 1 : 0
  })} ${units[i]}`;
};
const number = n => (n || 0).toLocaleString(locale);
const date = t => t ? new Date(t * 1000).toLocaleString(locale, {
  day: '2-digit',
  month: 'short',
  hour: '2-digit',
  minute: '2-digit'
}) : '—';
const duration = n => {
  if (n == null) return '—';
  n = Math.max(0, Math.round(n));
  return n < 60 ? `${n} ${t("s")}` : n < 3600 ? `${Math.floor(n / 60)} ${t("min")} ${n % 60} ${t("s")}` : `${Math.floor(n / 3600)} ${t("h")} ${Math.floor(n % 3600 / 60)} ${t("min")}`;
};
const speed = n => n >= 1e6 ? `${(n / 1e6).toFixed(2)} MH/s` : n >= 1000 ? `${(n / 1000).toFixed(1)} kH/s` : `${Math.round(n || 0)} H/s`;
const activeJob = () => state.jobs.find(j => ['queued', 'running', 'pausing', 'stopping', 'paused', 'interrupted'].includes(j.status));
const locked = () => !!state.jobs.find(j => ['queued', 'running', 'pausing', 'stopping', 'paused', 'interrupted'].includes(j.status));
const empty = (text, symbol = '◎') => `<div class="empty"><span class="empty-symbol">${symbol}</span>${esc(text)}</div>`;
const table = (head, body) => `<div class="table-scroll"><table><thead><tr>${head.map(x => `<th>${x}</th>`).join('')}</tr></thead><tbody>${body}</tbody></table></div>`;
async function api(url, {
  method = 'GET',
  body,
  form
} = {}) {
  const headers = {};
  if (method !== 'GET') headers['X-CSRF-Token'] = csrf;
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(body);
  }
  const response = await fetch(url, {
    method,
    headers,
    body: form || body
  });
  if (response.status === 401) {
    location.replace('/login');
    throw Error(t("Session expired"));
  }
  let result;
  try {
    result = await response.json();
  } catch {
    throw Error(t("Server unavailable. Try again later."));
  }
  if (!response.ok) throw Error(typeof result.detail === 'string' ? t(result.detail) : t("Check the entered values."));
  return result;
}
function toast(text, error = false) {
  const element = document.createElement('div');
  element.className = `toast${error ? ' error' : ''}`;
  element.textContent = text;
  $('#toasts').append(element);
  setTimeout(() => element.remove(), error ? 8500 : 4500);
}
async function action(fn) {
  if (busy) return;
  busy = true;
  try {
    await fn();
    await refresh();
  } catch (e) {
    toast(t(e.message), true);
  } finally {
    busy = false;
  }
}
function navigate(next) {
  if (!titles[next]) next = 'dashboard';
  page = next;
  $$('.page').forEach(e => e.classList.toggle('active', e.id === `page-${next}`));
  $$('.nav-item').forEach(e => e.classList.toggle('active', e.dataset.page === next));
  const [crumb, title, subtitle, eyebrow] = titles[next];
  $('#breadcrumb-page').textContent = crumb;
  $('#page-title').textContent = title;
  $('#page-subtitle').textContent = subtitle;
  $('#page-eyebrow').textContent = eyebrow;
  history.replaceState(null, '', `#${next}`);
  if (next === 'system') renderSystem();
  window.scrollTo({
    top: 0,
    behavior: 'instant'
  });
}
function openModal(title, content, eyebrow = t("WORKSPACE")) {
  modalReturnFocus = document.activeElement;
  $('#modal-title').textContent = title;
  $('#modal-eyebrow').textContent = eyebrow;
  $('#modal-body').innerHTML = content;
  if (!$('#modal').open) $('#modal').showModal();
  const field = $('#modal-body input');
  if (field) setTimeout(() => field.focus(), 40);
}
function closeModal() {
  $('#modal').close();
  if (modalReturnFocus?.isConnected) modalReturnFocus.focus();
}
$('#close-modal').addEventListener('click', closeModal);
$('#modal').addEventListener('click', e => {
  if (e.target === $('#modal')) {
    const r = e.target.getBoundingClientRect();
    if (e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom) closeModal();
  }
});
function hashStatus(hash) {
  if (hash.recovered) return 'found';
  const job = state.jobs.find(j => j.hash_ids.includes(hash.id) && ['running', 'queued', 'pausing', 'stopping', 'paused', 'interrupted'].includes(j.status));
  if (job) return job.status;
  return hash.passes ? 'exhausted' : 'neutral';
}
function networkRows(hashes, compact = false) {
  if (!hashes.length) return empty(t("Import your network capture to get started."));
  return table([t("NETWORK / SSID"), t("SOURCE"), t("STATUS"), compact ? t("PASSWORD") : t("PASSES"), ''], hashes.map(h => `<tr class="network-row" data-network="${h.id}" tabindex="0" role="button" aria-label="${esc(t("Open network"))} ${esc(h.ssid)}"><td><span class="network-name"><span class="network-icon">◎</span>${esc(h.ssid)}</span><span class="cell-sub mono">${esc(h.preview)}…</span></td><td><span>${esc(h.source.replace(/^HS_[A-Fa-f0-9]+_/, ''))}</span><span class="cell-sub">${date(h.created)}</span></td><td>${badge(hashStatus(h))}</td><td>${compact ? `<span class="mono muted">${h.recovered ? '••••••••' : '—'}</span>` : `<span class="mono">${h.passes}</span><span class="cell-sub">${duration(h.elapsed)}</span>`}</td><td class="table-action">↗</td></tr>`).join(''));
}
function render() {
  const selected = state.wordlists.filter(w => w.position);
  const recovered = state.hashes.filter(h => h.recovered).length;
  $('#networks-count').textContent = state.hashes.length;
  $('#sidebar-engine').textContent = state.worker_online ? t("Worker online") : t("Worker unavailable");
  $('#sidebar-status').classList.toggle('offline', !state.worker_online);
  const metrics = [[t("Wi-Fi networks"), new Set(state.hashes.map(h => h.ssid)).size, '◎', `${state.hashes.length} ${t("WPA records")}`, ''], [t("Passwords recovered"), recovered, '◈', `${state.hashes.length - recovered} ${t("records still unrecovered")}`, 'green'], [t("Queued dictionaries"), selected.length, '▤', `${state.wordlists.length} ${t("in the library")}`, ''], [t("Audit jobs"), state.total_jobs, '◷', t("Jobs saved on the server"), '']];
  $('#metrics').innerHTML = metrics.map(([label, value, icon, meta, color]) => `<div class="metric"><div class="metric-label">${label}<span class="metric-icon">${icon}</span></div><div class="metric-value ${color}">${number(value)}</div><div class="metric-meta"><span class="metric-bar ${color}"></span>${meta}</div></div>`).join('');
  $('#queue-count').textContent = selected.length;
  $('#dashboard-queue').innerHTML = selected.length ? selected.map(w => `<div class="queue-row"><span class="queue-number">${String(w.position).padStart(2, '0')}</span><div class="queue-name">${esc(w.name)}<span class="queue-source">${number(w.lines)} ${esc(t("lines \xB7"))} ${esc(t(w.source))}</span></div><span class="queue-size">${bytes(w.bytes)}</span><span class="queue-end">↗</span></div>`).join('') : empty(t("Select dictionaries from the library."), '▤');
  $('#dashboard-networks').innerHTML = networkRows(state.hashes.slice(0, 5), true);
  renderNetworks();
  renderWordlists();
  renderRun();
  renderHistory();
  const startDisabled = locked() || !state.worker_online || !selected.length || !state.hashes.some(h => !h.recovered);
  $('#start-job').disabled = startDisabled;
  $('#add-capture').disabled = locked();
  $('#reset-workspace').disabled = locked() || !state.hashes.length;
}
function renderNetworks() {
  const search = $('#network-search').value.toLowerCase();
  $('#networks-table').innerHTML = networkRows(state.hashes.filter(h => `${h.ssid} ${h.source}`.toLowerCase().includes(search)));
}
function renderWordlists() {
  const query = $('#wordlist-search').value.toLowerCase();
  const words = state.wordlists.filter(w => `${w.name} ${w.source}`.toLowerCase().includes(query));
  const selected = state.wordlists.filter(w => w.position);
  $('#wordlists-table').innerHTML = words.length ? table([t("QUEUE"), t("DICTIONARY / SOURCE"), t("SIZE"), t("LINES"), t("ORDER")], words.map(w => `<tr><td><button class="wordlist-select ${w.position ? 'selected' : ''}" data-toggle-word="${w.id}" ${locked() ? 'disabled' : ''} aria-label="${w.position ? t("Remove from queue") : t("Add to queue")} ${esc(w.name)}">${w.position ? String(w.position).padStart(2, '0') : '＋'}</button></td><td><div class="wordlist-name">${esc(w.name)}</div><span class="cell-sub">${esc(t(w.source))}</span></td><td class="mono muted">${bytes(w.bytes)}</td><td class="mono muted">${number(w.lines)}</td><td><div class="row-buttons"><button class="icon-button" data-move-word="${w.id}" data-direction="-1" title="${esc(t("Move up"))}" ${locked() || !w.position || w.position === 1 ? 'disabled' : ''}>↑</button><button class="icon-button" data-move-word="${w.id}" data-direction="1" title="${esc(t("Move down"))}" ${locked() || !w.position || w.position === selected.length ? 'disabled' : ''}>↓</button><button class="icon-button danger-text" data-delete-word="${w.id}" title="${esc(t("Delete dictionary"))}" ${locked() ? 'disabled' : ''}>×</button></div></td></tr>`).join('')) : empty(t("No dictionaries found. Upload a file or open GitHub."), '▤');
}
function renderRun() {
  const job = activeJob() || state.jobs[0];
  if (!job) {
    $('#run-status').className = 'badge neutral';
    $('#run-status').textContent = t("Ready");
    $('#current-run').innerHTML = `<div class="idle-run"><div class="idle-title">${esc(t("Ready to audit?"))}</div><p>${esc(t("Import your network capture, choose dictionaries"))}<br>${esc(t("and run the queue on your server."))}</p><div class="idle-foot"><span class="status-dot"></span> WPA / PBKDF2 · MODE 22000</div></div>`;
    return;
  }
  $('#run-status').className = `badge ${job.status}`;
  $('#run-status').textContent = names[job.status] || job.status;
  const p = job.progress || {};
  const percent = Number(p.percent || 0);
  const ended = ['completed', 'stopped', 'failed'].includes(job.status);
  const eta = typeof p.eta === 'number' ? duration(p.eta - Date.now() / 1000) : '—';
  let controls = '';
  if (job.status === 'running') controls = `<button class="button secondary" data-job-action="pause" data-job="${job.id}">${esc(t("\u2161 Pause"))}</button><button class="button secondary" data-job-action="skip" data-job="${job.id}">${esc(t("Next dictionary \u2192"))}</button><button class="button secondary danger-text" data-job-action="stop" data-job="${job.id}">${esc(t("\u25A0 Stop"))}</button>`;else if (['paused', 'interrupted'].includes(job.status)) controls = `<button class="button primary" data-job-action="resume" data-job="${job.id}">${esc(t("Resume \u2197"))}</button><button class="button secondary danger-text" data-job-action="stop" data-job="${job.id}">${esc(t("Stop"))}</button>`;else if (job.status === 'queued') controls = `<button class="button secondary danger-text" data-job-action="stop" data-job="${job.id}">${esc(t("Cancel job"))}</button>`;else if (ended) controls = `<button class="text-button" data-go="history">${esc(t("View history \u2197"))}</button>`;
  $('#current-run').innerHTML = `<div class="run-content"><div class="run-title-row"><div class="run-wordlist" title="${esc(p.wordlist || job.name)}">${esc(p.wordlist || job.name)}</div><div class="run-percent">${percent.toFixed(1)}<small>%</small></div></div><progress value="${percent}" max="100" aria-label="${esc(t("Pass progress"))}"></progress><div class="run-stats"><div><span>${ended ? t("Result") : t("Speed")}</span><strong>${ended ? `${state.hashes.filter(h => h.recovered && job.hash_ids.includes(h.id)).length} / ${job.hash_ids.length} ${t("recovered")}` : speed(p.speed || 0)}</strong></div><div><span>${ended ? t("Job duration") : t("Remaining")}</span><strong>${ended ? duration((job.finished || Date.now() / 1000) - (job.started || job.created)) : eta}</strong></div><div><span>${esc(t("Dictionary"))}</span><strong>${ended ? Math.min(job.next_index + 1, job.wordlists.length) : p.pass_index || 1} / ${job.wordlists.length}</strong></div></div>${controls ? `<div class="run-actions">${controls}</div>` : ''}${job.error ? `<div class="job-error">${esc(t(job.error))}</div>` : ''}${job.status === 'paused' ? `<div class="field-hint">${esc(t("Resume uses a checkpoint. If none was written, the current dictionary starts again."))}</div>` : ''}</div>`;
}
function renderHistory() {
  $('#jobs-table').innerHTML = state.jobs.length ? table([t("JOB"), t("STARTED"), t("DICTIONARIES"), t("STATUS"), ''], state.jobs.map(j => `<tr><td><span class="job-name">${esc(j.name)}</span><span class="cell-sub">${j.hash_ids.length} ${esc(t("WPA records \xB7"))} ${duration((j.finished || Date.now() / 1000) - (j.started || j.created))}</span></td><td>${date(j.created)}</td><td class="mono muted">${j.wordlists.length}</td><td>${badge(j.status)}</td><td><button class="text-button" data-job-detail="${j.id}">${esc(t("Details \u2197"))}</button></td></tr>`).join('')) : empty(t("Your audit jobs will appear here."), '◷');
  $('#attempts-table').innerHTML = state.attempts.length ? table([t("DICTIONARY"), t("STARTED"), t("DURATION"), t("RECOVERED"), t("RESULT"), ''], state.attempts.map(a => `<tr><td><span class="wordlist-name">${esc(a.wordlist_name)}</span><span class="cell-sub mono">${esc(t("Job"))} ${a.job_id.slice(0, 8)} ${esc(t("\xB7 pass"))} ${a.pass_index + 1}</span></td><td>${date(a.started)}</td><td class="mono muted">${duration((a.finished || Date.now() / 1000) - a.started)}</td><td class="mono">${a.recovered}</td><td>${badge(a.outcome)}</td><td><button class="text-button" data-log="${a.id}">${esc(t("Log \u2197"))}</button></td></tr>`).join('')) : empty(t("No dictionary passes yet."), '▤');
}
function renderSystem() {
  if (!system) {
    $('#system-details').innerHTML = empty(t("Loading server status\u2026"), '▧');
    return;
  }
  const g = system.gpu;
  const card = (label, title, rows) => `<section class="panel system-card"><span class="eyebrow">${label}</span><h3>${title}</h3>${rows.map(([name, value]) => `<div class="system-row"><span>${name}</span><span>${esc(value)}</span></div>`).join('')}</section>`;
  $('#system-details').innerHTML = `<div class="system-grid">${card(t("ACCELERATOR"), g.name || t("GPU unavailable"), [[t("Status"), g.available ? t("Online") : t("Not available")], [t("Driver"), g.driver || '—'], [t("Temperature"), g.temperature == null ? '—' : `${g.temperature} °C`], [t("Utilization"), g.utilization == null ? '—' : `${g.utilization}%`], [t("Memory"), g.memory_total ? `${g.memory_used} / ${g.memory_total} ${t("MB")}` : '—'], [t("Power"), g.power == null ? '—' : `${g.power} ${t("W")}`]])}${card(t("ENGINE"), 'Hashcat / WPA', [['Worker', system.worker_online ? t("Online") : t("Unavailable")], ['Hashcat', system.engine.hashcat || '—'], ['hcxpcapngtool', (system.engine.converter || '—').split('\n')[0]], [t("Mode"), t("22000 \xB7 dictionary")], [t("Accelerator"), 'NVIDIA OpenCL'], [t("Temperature cutoff"), '85 °C']])}${card(t("HOST"), t("Server host"), [[t("System"), 'Debian 13'], [t("CPU threads"), system.cpu_threads], [t("Load"), system.load.toFixed(2)], [t("Free disk space"), bytes(system.disk.free)], [t("Computation"), t("One GPU job at a time")], [t("Working files"), t("Private server storage")]])}</div>`;
}
async function refresh() {
  if (refreshing) return;
  refreshing = true;
  try {
    state = await api('/api/state');
    render();
  } catch (e) {
    toast(t(e.message), true);
  } finally {
    refreshing = false;
  }
}
async function refreshSystem() {
  try {
    system = await api('/api/system');
    const g = system.gpu;
    $('#gpu-temp').textContent = g.temperature ?? '—';
    $('#gpu-load').textContent = g.utilization == null ? '—' : `${g.utilization}%`;
    $('#gpu-memory').textContent = g.memory_total ? `${(g.memory_used / 1024).toFixed(1)} / ${(g.memory_total / 1024).toFixed(0)} ${t("GB")}` : '—';
    if (g.temperature != null) {
      temps.push(g.temperature);
      temps = temps.slice(-60);
      const plot = temps.length === 1 ? [temps[0], temps[0]] : temps;
      $('#temp-line').setAttribute('d', plot.map((v, i) => `${i ? 'L' : 'M'}${(i / (plot.length - 1) * 300).toFixed(1)} ${(60 - (v - 25) / 60 * 55).toFixed(1)}`).join(' '));
    }
    if (page === 'system') renderSystem();
  } catch (e) {
    console.warn('Telemetry unavailable');
  }
}
function upload(url, file) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    const data = new FormData();
    data.append('file', file);
    xhr.open('POST', url);
    xhr.setRequestHeader('X-CSRF-Token', csrf);
    xhr.upload.onprogress = e => {
      if (e.lengthComputable) {
        const bar = $('#upload-progress');
        if (bar) bar.value = e.loaded / e.total * 100;
        const label = $('#upload-label');
        if (label) label.textContent = e.loaded === e.total ? t("File received. Processing\u2026") : `${t("Uploading")} ${Math.round(e.loaded / e.total * 100)}%`;
      }
    };
    xhr.onload = () => {
      let result;
      try {
        result = JSON.parse(xhr.responseText);
      } catch {
        return reject(Error(t("The server rejected the file. The proxy upload limit may have been exceeded.")));
      }
      if (xhr.status === 401) {
        location.replace('/login');
        return;
      }
      if (xhr.status >= 200 && xhr.status < 300) resolve(result);else reject(Error(t(result.detail) || t("File upload failed")));
    };
    xhr.onerror = () => reject(Error(t("Connection interrupted. Retry the upload.")));
    xhr.timeout = 600000;
    xhr.ontimeout = () => reject(Error(t("The upload timed out.")));
    xhr.send(data);
  });
}
async function uploadFiles(kind, files) {
  if (!files.length || busy) return;
  busy = true;
  openModal(kind === 'capture' ? t("Importing network") : t("Importing dictionaries"), `<p class="muted small" id="upload-filename"></p><progress class="upload-bar" id="upload-progress" max="100" value="0"></progress><p class="field-hint" id="upload-label">${esc(t("Preparing upload\u2026"))}</p>`, t("IMPORT / LOCAL FILE"));
  try {
    for (const file of files) {
      if (file.size > (kind === 'capture' ? 64 * 1024 * 1024 : 2 * 1024 ** 3)) throw Error(kind === 'capture' ? t("Captures must be no larger than 64 MB.") : t("Dictionaries must be no larger than 2 GB."));
      $('#upload-filename').textContent = `${file.name} · ${bytes(file.size)}`;
      const result = await upload(kind === 'capture' ? '/api/captures' : '/api/wordlists', file);
      toast(kind === 'capture' ? `${t("Records added:")} ${result.added}${t(". Duplicates:")} ${result.duplicates}.` : result.duplicate ? t("This dictionary is already in the library.") : `${t("Dictionary")} ${file.name} ${t("added.")}`);
    }
    closeModal();
    await refresh();
    navigate(kind === 'capture' ? 'networks' : 'wordlists');
  } catch (e) {
    $('#modal-body').innerHTML = `<div class="form-error">${esc(t(e.message))}</div><div class="modal-actions"><button class="button secondary" data-close-modal>${esc(t("Close"))}</button></div>`;
  } finally {
    busy = false;
  }
}
function startDialog() {
  const available = state.hashes.filter(h => !h.recovered);
  openModal(t("New audit"), `<form id="start-form" class="form-grid"><div class="field"><label for="job-name">${esc(t("Job name"))}</label><input id="job-name" maxlength="100" value="${esc(t("Wi-Fi audit"))}" required></div><div class="field"><label>${esc(t("Networks to audit"))}</label><div class="network-selection">${available.map(h => `<label class="network-choice"><input type="checkbox" name="hash" value="${h.id}" checked><span>${esc(h.ssid)} <small class="muted">· ${esc(h.source.replace(/^HS_[A-Fa-f0-9]+_/, ''))}</small></span></label>`).join('')}</div></div><div class="field"><label for="workload">${esc(t("GPU workload"))}</label><select id="workload"><option value="1">${esc(t("Low \xB7 server is handling other work"))}</option><option value="2" selected>${esc(t("Normal \xB7 recommended"))}</option><option value="3">${esc(t("High \xB7 maximum GPU resources"))}</option></select></div><div class="field"><label for="runtime">${esc(t("Time limit per pass, minutes"))}</label><input id="runtime" type="number" min="0" max="1440" value="0"><p class="field-hint">${esc(t("0 means no limit. The job pauses when the limit is reached."))}</p></div><p class="muted small">${state.wordlists.filter(w => w.position).length} ${esc(t("dictionaries \xB7 WPA 22000 \xB7 dictionary checks only."))}</p><div class="form-error" id="start-error"></div><div class="modal-actions"><button type="button" class="button secondary" data-close-modal>${esc(t("Cancel"))}</button><button class="button primary" type="submit">${esc(t("Run on server \u2197"))}</button></div></form>`, t("NEW JOB / SERVER GPU"));
  $('#start-form').addEventListener('submit', async e => {
    e.preventDefault();
    const button = e.target.querySelector('[type=submit]');
    button.disabled = true;
    try {
      await api('/api/jobs', {
        method: 'POST',
        body: {
          name: $('#job-name').value,
          hash_ids: $$('input[name=hash]:checked').map(x => x.value),
          runtime: Math.round(Number($('#runtime').value) * 60),
          workload: Number($('#workload').value)
        }
      });
      closeModal();
      navigate('dashboard');
      toast(t("Audit queued."));
      await refresh();
    } catch (error) {
      $('#start-error').textContent = t(error.message);
      button.disabled = false;
    }
  });
}
async function networkDetail(id) {
  try {
    const h = await api(`/api/hashes/${id}`);
    openModal(h.ssid, `<div class="detail-summary">${badge(h.recovered ? 'found' : hashStatus(h))}<span class="muted small">${esc(h.source)}</span></div><div class="detail-section"><div class="detail-label">WPA / HASHCAT 22000</div><div class="hash-code">${esc(h.hash)}</div></div><div class="detail-section"><div class="detail-label">${esc(t("PASSWORD"))}</div><div id="password-value" class="password-value">${h.recovered ? '••••••••' : t("Not recovered yet")}</div>${h.recovered ? `<div class="password-toolbar"><button class="text-button" id="reveal-password">${esc(t("Show password"))}</button><button class="text-button" id="copy-password" disabled>${esc(t("Copy"))}</button></div>` : ''}</div><div class="detail-section"><div class="detail-label">${esc(t("NETWORK HISTORY"))}</div>${h.passes.length ? `<div class="details-table">${table([t("DICTIONARY"), t("TIME"), t("RESULT")], h.passes.map(p => `<tr><td>${esc(p.wordlist_name)}<span class="cell-sub">${date(p.started)}</span></td><td>${duration((p.finished || Date.now() / 1000) - p.started)}</td><td>${badge(p.outcome)}</td></tr>`).join(''))}</div>` : empty(t("No passes yet."), '◷')}</div><p class="field-hint">${esc(t("History shows the duration of the entire pass, not the exact time a password was recovered."))}</p>`, t("NETWORK / SESSION HISTORY"));
    if (h.recovered) {
      let value = null;
      $('#reveal-password').addEventListener('click', async () => {
        try {
          if (value === null) {
            const data = await api(`/api/hashes/${id}/password`);
            value = data.password;
          }
          const shown = $('#reveal-password').textContent === t("Hide password");
          $('#password-value').textContent = shown ? '••••••••' : value;
          $('#reveal-password').textContent = shown ? t("Show password") : t("Hide password");
          $('#copy-password').disabled = shown;
        } catch (e) {
          toast(t(e.message), true);
        }
      });
      $('#copy-password').addEventListener('click', async () => {
        try {
          await navigator.clipboard.writeText(value);
          toast(t("Password copied."));
        } catch {
          toast(t("Select the password and copy it manually."), true);
        }
      });
    }
  } catch (e) {
    toast(t(e.message), true);
  }
}
function confirmModal(title, text, onConfirm, requireText = false) {
  openModal(title, `<p class="muted small">${esc(text)}</p>${requireText ? `<div class="field"><label for="confirm-value">${esc(t("Type CLEAR"))}</label><input id="confirm-value" autocomplete="off"></div>` : ''}<div class="form-error" id="confirm-error"></div><div class="modal-actions"><button class="button secondary" data-close-modal>${esc(t("Cancel"))}</button><button class="button danger" id="confirm-action">${requireText ? t("Clear") : t("Confirm")}</button></div>`, t("CONFIRM / WORKSPACE"));
  $('#confirm-action').addEventListener('click', async () => {
    const button = $('#confirm-action');
    button.disabled = true;
    try {
      await onConfirm(requireText ? $('#confirm-value').value : null);
      closeModal();
      await refresh();
    } catch (e) {
      $('#confirm-error').textContent = t(e.message);
      button.disabled = false;
    }
  });
}
function githubDialog() {
  githubStamp = '';
  openModal(t("GitHub dictionaries"), `<form id="github-form" class="github-search"><input id="github-repository" placeholder="danielmiessler/SecLists" required aria-label="${esc(t("Public repository"))}"><button class="button primary" type="submit">${esc(t("Find files \u2197"))}</button></form><p class="field-hint">${esc(t("Public text files up to 50 MB. Hashes and passwords are never sent to GitHub."))}</p><div id="github-results"></div>`, t("DICTIONARIES / GITHUB"));
  $('#github-form').addEventListener('submit', async e => {
    e.preventDefault();
    const button = e.target.querySelector('button');
    button.disabled = true;
    $('#github-results').innerHTML = `<div class="loading-state">${esc(t("Reading repository catalog\u2026"))}</div>`;
    try {
      const result = await api('/api/github/catalog', {
        method: 'POST',
        body: {
          repository: $('#github-repository').value
        }
      });
      githubStamp = result.stamp;
      $('#github-results').innerHTML = `<p class="field-hint">Commit ${esc(result.commit.slice(0, 8))}${result.truncated ? ` ${t("\xB7 Partial catalog shown")}` : ''}</p>` + (result.files.length ? result.files.map(f => `<div class="github-file"><span>${esc(f.path)}<small>${bytes(f.bytes)}</small></span><button class="button secondary" data-github-file="${esc(f.path)}">${esc(t("Add"))}</button></div>`).join('') : empty(t("No matching files."), '▤'));
    } catch (error) {
      $('#github-results').innerHTML = `<div class="form-error">${esc(t(error.message))}</div>`;
    } finally {
      button.disabled = false;
    }
  });
}
document.addEventListener('click', event => {
  const e = event.target.closest('button,[data-network]');
  if (!e) return;
  if (e.dataset.page) navigate(e.dataset.page);
  if (e.dataset.go) navigate(e.dataset.go);
  if (e.hasAttribute('data-close-modal')) closeModal();
  if (e.dataset.network) networkDetail(e.dataset.network);
  if (e.dataset.toggleWord) action(async () => {
    const ids = state.wordlists.filter(w => w.position).map(w => w.id);
    const i = ids.indexOf(e.dataset.toggleWord);
    if (i < 0) ids.push(e.dataset.toggleWord);else ids.splice(i, 1);
    await api('/api/queue', {
      method: 'PUT',
      body: {
        ids
      }
    });
  });
  if (e.dataset.moveWord) action(async () => {
    const ids = state.wordlists.filter(w => w.position).map(w => w.id);
    const i = ids.indexOf(e.dataset.moveWord),
      n = i + Number(e.dataset.direction);
    if (n >= 0 && n < ids.length) {
      [ids[i], ids[n]] = [ids[n], ids[i]];
      await api('/api/queue', {
        method: 'PUT',
        body: {
          ids
        }
      });
    }
  });
  if (e.dataset.deleteWord) {
    const word = state.wordlists.find(w => w.id === e.dataset.deleteWord);
    confirmModal(t("Delete this dictionary?"), `${word.name} ${t("will be removed from the library and queue.")}`, () => api(`/api/wordlists/${word.id}`, {
      method: 'DELETE'
    }));
  }
  if (e.dataset.jobAction) {
    const fn = () => api(`/api/jobs/${e.dataset.job}/${e.dataset.jobAction}`, {
      method: 'POST'
    });
    if (['stop', 'skip'].includes(e.dataset.jobAction)) confirmModal(e.dataset.jobAction === 'stop' ? t("Stop this audit?") : t("Skip this dictionary?"), e.dataset.jobAction === 'stop' ? t("Recovered results and history will be kept.") : t("The current pass will end and the queue will continue with the next dictionary."), fn);else action(fn);
  }
  if (e.dataset.log) {
    openModal(t("Pass log"), `<div class="loading-state">${esc(t("Loading log\u2026"))}</div>`, t("HASHCAT / ENGINE OUTPUT"));
    api(`/api/attempts/${e.dataset.log}/log`).then(data => {
      $('#modal-body').innerHTML = '<pre class="log-view"></pre>';
      $('.log-view').textContent = data.text.split('\n').map(line => t(line)).join('\n');
    }).catch(err => {
      $('#modal-body').textContent = t(err.message);
    });
  }
  if (e.dataset.jobDetail) {
    const j = state.jobs.find(j => j.id === e.dataset.jobDetail);
    openModal(j.name, `<div class="detail-summary">${badge(j.status)}<span class="mono muted">${j.id.slice(0, 12)}</span></div><div class="detail-section"><div class="detail-label">${esc(t("NETWORKS"))}</div><p>${esc(j.hash_ids.map(id => state.hashes.find(h => h.id === id)?.ssid || t("Deleted")).join(', '))}</p></div><div class="detail-section"><div class="detail-label">${esc(t("QUEUE SNAPSHOT"))}</div>${j.wordlists.map((w, i) => `<div class="queue-row"><span class="queue-number">${String(i + 1).padStart(2, '0')}</span><span class="queue-name">${esc(w.name)}</span><span class="queue-size">${bytes(w.bytes)}</span></div>`).join('')}</div><p class="muted small">${esc(t("Created"))} ${date(j.created)} · ${j.runtime ? `${t("Limit")} ${duration(j.runtime)} ${t("per pass")}` : t("No time limit")} ${esc(t("\xB7 Workload"))} ${j.workload}</p>${j.error ? `<div class="job-error">${esc(t(j.error))}</div>` : ''}`, t("JOB / SAVED SNAPSHOT"));
  }
  if (e.dataset.githubFile) {
    e.disabled = true;
    e.textContent = t("Downloading\u2026");
    api('/api/github/import', {
      method: 'POST',
      body: {
        stamp: githubStamp,
        path: e.dataset.githubFile
      }
    }).then(result => {
      e.textContent = result.duplicate ? t("Already present") : t("Added");
      toast(t("Dictionary available in the library."));
      refresh();
    }).catch(error => {
      e.disabled = false;
      e.textContent = t("Add");
      toast(t(error.message), true);
    });
  }
});
document.addEventListener('keydown', e => {
  if ((e.key === 'Enter' || e.key === ' ') && e.target.dataset.network) {
    e.preventDefault();
    networkDetail(e.target.dataset.network);
  }
});
$('#logout').addEventListener('click', () => action(async () => {
  await api('/api/logout', {
    method: 'POST'
  });
  location.replace('/login');
}));
$('#add-capture').addEventListener('click', () => $('#capture-file').click());
$('#add-wordlist').addEventListener('click', () => $('#wordlist-files').click());
$('#capture-file').addEventListener('change', e => {
  uploadFiles('capture', [...e.target.files]);
  e.target.value = '';
});
$('#wordlist-files').addEventListener('change', e => {
  uploadFiles('wordlist', [...e.target.files]);
  e.target.value = '';
});
$('#network-search').addEventListener('input', renderNetworks);
$('#wordlist-search').addEventListener('input', renderWordlists);
$('#start-job').addEventListener('click', startDialog);
$('#open-github').addEventListener('click', githubDialog);
$('#export-results').addEventListener('click', () => {
  confirmModal(t("Export results?"), t("The CSV contains recovered passwords. Store it securely."), async () => {
    const response = await fetch('/api/export');
    if (!response.ok) throw Error(t("Could not download results."));
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'wifi-audit-results.csv';
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
});
$('#reset-workspace').addEventListener('click', () => confirmModal(t("Clear the workspace?"), t("Captures, hashes, results and job history will be deleted. Dictionaries and queue order will be kept."), confirmation => api('/api/reset', {
  method: 'POST',
  body: {
    confirmation
  }
}), true));
navigate(location.hash.slice(1) || 'dashboard');
refresh();
refreshSystem();
setInterval(() => {
  if (!document.hidden) refresh();
}, 2500);
setInterval(() => {
  if (!document.hidden) refreshSystem();
}, 5000);
document.addEventListener('visibilitychange', () => {
  if (!document.hidden) {
    refresh();
    refreshSystem();
  }
});
function clock() {
  $('#clock').textContent = new Date().toLocaleTimeString(locale, {
    hour: '2-digit',
    minute: '2-digit'
  });
}
clock();
setInterval(clock, 30000);
$('#account').addEventListener('click', () => {
  openModal(t("Account access"), `<form id="password-form" class="form-grid"><div class="field"><label for="current-password">${esc(t("Current password"))}</label><input id="current-password" type="password" autocomplete="current-password" required></div><div class="field"><label for="new-password">${esc(t("New password"))}</label><input id="new-password" type="password" autocomplete="new-password" minlength="14" maxlength="200" required><p class="field-hint">${esc(t("At least 14 characters. Changing it signs out all sessions."))}</p></div><div class="field"><label for="repeat-password">${esc(t("Confirm new password"))}</label><input id="repeat-password" type="password" autocomplete="new-password" required></div><div class="form-error" id="password-error"></div><div class="modal-actions"><button type="button" class="button secondary" id="account-logout">${esc(t("Sign out"))}</button><button type="submit" class="button primary">${esc(t("Change password"))}</button></div></form>`, t("ACCOUNT / PRIVATE ACCESS"));
  $('#account-logout').addEventListener('click', async () => {
    await api('/api/logout', {
      method: 'POST'
    });
    location.replace('/login');
  });
  $('#password-form').addEventListener('submit', async e => {
    e.preventDefault();
    const button = e.target.querySelector('[type=submit]');
    try {
      if ($('#new-password').value !== $('#repeat-password').value) throw Error(t("The new passwords do not match."));
      button.disabled = true;
      await api('/api/profile/password', {
        method: 'POST',
        body: {
          current: $('#current-password').value,
          new: $('#new-password').value
        }
      });
      location.replace('/login');
    } catch (error) {
      $('#password-error').textContent = t(error.message);
      button.disabled = false;
    }
  });
});
}).catch(() => { document.body.dataset.localeError = 'true'; });
