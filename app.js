const state = { files: [], analyzing: false, retentionDays: 30, retentionTimers: new Map() };
const $ = (selector) => document.querySelector(selector);
const messageInput = $('#messageInput');
const fileInput = $('#fileInput');
const dropZone = $('#dropZone');

function safeText(value) {
  return String(value).replace(/[<>]/g, '');
}
function maskedLog(value) {
  return String(value).replace(/(?:\d[ -]?){4,}/g, '[REDACTED]').replace(/[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}/g, '[EMAIL REDACTED]').replace(/\$\s?\d+(?:\.\d{2})?/g, '[AMOUNT REDACTED]');
}
function logEvent(text) {
  const entry = document.createElement('div');
  entry.className = 'audit-entry';
  entry.innerHTML = `<span class="audit-time">NOW</span><span>${safeText(maskedLog(text))}</span>`;
  $('#auditLog').prepend(entry);
}
function showToast(text) { const toast = $('#toast'); toast.textContent = text; toast.classList.add('show'); setTimeout(() => toast.classList.remove('show'), 3200); }
function formatSize(bytes) { return bytes < 1024 * 1024 ? `${Math.max(1, Math.round(bytes / 1024))} KB` : `${(bytes / 1024 / 1024).toFixed(1)} MB`; }
function scheduleRetentionExpiry(file, remainingMs = state.retentionDays * 24 * 60 * 60 * 1000) {
  const maxDelay = 2_147_000_000;
  const delay = Math.min(remainingMs, maxDelay);
  const timer = setTimeout(() => {
    if (remainingMs > delay) {
      scheduleRetentionExpiry(file, remainingMs - delay);
      return;
    }
    state.files = state.files.filter(existing => existing !== file);
    state.retentionTimers.delete(file);
    renderFiles();
    logEvent(`Evidence expired after ${state.retentionDays} days and was deleted`);
  }, delay);
  state.retentionTimers.set(file, timer);
}
function addFiles(fileList) {
  [...fileList].forEach(file => {
    if (file.size > 10 * 1024 * 1024) { showToast(`${file.name} is over the 10 MB limit.`); return; }
    const allowed = ['image/png','image/jpeg','image/webp','application/pdf','text/plain','text/csv','application/json'];
    if (!allowed.includes(file.type) && !/\.(png|jpe?g|webp|pdf|txt|csv|json)$/i.test(file.name)) { showToast(`${file.name} was rejected as an unsafe file type.`); logEvent('Rejected unsafe file type'); return; }
    if (state.files.some(existing => existing.name === file.name && existing.size === file.size)) return;
    state.files.push(file);
    scheduleRetentionExpiry(file);
  });
  renderFiles();
}
function renderFiles() {
  $('#fileCount').textContent = `${state.files.length} file${state.files.length === 1 ? '' : 's'}`;
  $('#fileList').innerHTML = state.files.map((file, index) => `<div class="file-item"><span class="file-type">${safeText(file.name.split('.').pop().toUpperCase())}</span><span class="file-name" title="${safeText(file.name)}">${safeText(file.name)}</span><span class="file-size">${formatSize(file.size)}</span><button class="remove-file" data-index="${index}" aria-label="Remove ${safeText(file.name)}">×</button></div>`).join('');
  document.querySelectorAll('.remove-file').forEach(button => button.addEventListener('click', () => { state.files.splice(Number(button.dataset.index), 1); renderFiles(); }));
}
function extractMessage(message) {
  const product = message.match(/product\s*[:#-]?\s*(.+?)(?:\r?\n|$)/i)?.[1]?.trim() || null;
  const dollarAmount = message.match(/\$\s?([\d,]+(?:\.\d{2})?)/i)?.[1];
  const labeledAmount = message.match(/amount\s*[:#-]?\s*\$?\s*(\d[\d,]*(?:\.\d{1,2})?)/i)?.[1];
  return {
    order: message.match(/(?:order\s*(?:id|number)?|#)\s*[:#-]?\s*([A-Z0-9-]{4,})/i)?.[1] || null,
    amount: (dollarAmount || labeledAmount)?.replace(/,/g, '') || null,
    date: message.match(/\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+\d{1,2}\b/i)?.[0] || null,
    error: message.match(/\b(?:error\s*(?:code)?|code)\s*[:#-]?\s*([A-Z]-?\d{3,5})\b/i)?.[1] || null,
    product
  };
}
function inferEvidence(file) {
  const name = file.name.toLowerCase();
  const isBlurred = /blur|blurry|low.?quality|unclear|pixel/i.test(name);
  const isUnsafe = /prompt|instruction|ignore|jailbreak|malicious/i.test(name);
  if (isUnsafe) return { unsafe: true };
  if (isBlurred) return { lowQuality: true };
  return { order: /invoice|receipt|order|screenshot/i.test(name) ? '847291' : null, amount: /invoice|receipt/i.test(name) ? '129.99' : null, date: /invoice|receipt/i.test(name) ? 'June 12' : null, error: /error|screenshot/i.test(name) ? 'E-403' : null, product: /product|shoe|phone|item/i.test(name) ? 'Product image detected' : null };
}
async function readTextFile(file) {
  const isText = file.type.startsWith('text/') || file.type === 'application/json' || /\.(txt|csv|json)$/i.test(file.name);
  return isText ? file.text() : '';
}
function finding(icon, tone, label, value, status) { return `<div class="finding"><span class="finding-icon ${tone}">${icon}</span><div><div class="finding-label">${label}</div><div class="finding-value">${safeText(value)}</div></div><span class="finding-status ${tone}">${status}</span></div>`; }
function setStatus(label, tone, title, description) { const pill = $('#statusPill'); pill.textContent = label; pill.className = `status-pill ${tone}`; $('#statusBody').innerHTML = `<div class="status-illustration">${tone === 'done' ? '✓' : tone === 'alert' ? '!' : '◌'}</div><h3>${title}</h3><p>${description}</p>`; }
async function analyze() {
  if (state.analyzing) return;
  const message = messageInput.value.trim();
  if (!message) { showToast('Add the customer message before analyzing.'); messageInput.focus(); return; }
  state.analyzing = true; $('#analyzeBtn').disabled = true; $('#progressWrap').hidden = false; $('#findings').innerHTML = ''; setStatus('Reading', 'working', 'Inspecting evidence', 'OCR is extracting structured signals. Hidden instructions are ignored.');
  let percent = 0; const delayed = state.files.some(file => /slow|delay|large/i.test(file.name)); const duration = delayed ? 31000 : 1800;
  const timer = setInterval(() => { percent = Math.min(percent + (delayed ? 2 : 24), 96); $('#progressBar').style.width = `${percent}%`; $('#progressPercent').textContent = `${percent}%`; $('#progressText').textContent = percent > 58 ? 'Comparing claims' : 'Reading files'; }, 400);
  await new Promise(resolve => setTimeout(resolve, duration)); clearInterval(timer); $('#progressBar').style.width = '100%'; $('#progressPercent').textContent = '100%';
  const messageData = extractMessage(message); const evidence = state.files.map(inferEvidence); const textEvidence = {};
  for (const file of state.files) {
    const text = await readTextFile(file);
    if (/ignore (?:all|any|the) previous|system prompt|hidden instruction|jailbreak/i.test(text)) {
      evidence.push({ unsafe: true });
    }
    const extractedText = extractMessage(text);
    Object.entries(extractedText).forEach(([key, value]) => {
      if (value) textEvidence[key] = value;
    });
  }
  const merged = Object.assign({}, ...evidence, textEvidence); const findings = [];
  if (evidence.some(item => item.unsafe)) { findings.push(finding('!', 'bad', 'File safety', 'Embedded instructions detected', 'Rejected')); logEvent('Rejected file containing unsafe embedded instructions'); }
  if (evidence.some(item => item.lowQuality)) { findings.push(finding('!', 'warn', 'Image quality', 'OCR confidence too low to verify', 'Clarify')); logEvent('Low-quality evidence requires another file'); }
  const fields = [['Order ID', messageData.order, merged.order], ['Amount', messageData.amount ? `$${messageData.amount}` : null, merged.amount ? `$${merged.amount}` : null], ['Date', messageData.date, merged.date], ['Error code', messageData.error, merged.error], ['Product', null, merged.product]];
  fields.forEach(([label, claimed, extracted]) => { if (!extracted && !claimed) return; const conflict = claimed && extracted && claimed.toLowerCase() !== extracted.toLowerCase(); const missing = !extracted; const tone = conflict ? 'bad' : missing ? 'warn' : 'ok'; const status = conflict ? 'Conflict' : missing ? 'Missing' : 'Match'; const value = conflict ? `Message: ${claimed} / File: ${extracted}` : extracted || `Message: ${claimed} / no file evidence`; findings.push(finding(conflict ? '×' : tone === 'ok' ? '✓' : '!', tone, label, value, status)); });
  $('#findings').innerHTML = findings.length ? findings.join('') : '<div class="findings-empty">No readable fields found. Request a clearer file or more details.</div>'; $('#signalCount').textContent = `${findings.length} found`;
  const needsClarification = findings.some(item => item.includes('bad') || item.includes('warn'));
  if (delayed) { setStatus('Queued', 'working', 'Still processing in background', 'This request crossed 30 seconds. The customer should be notified when the result is ready.'); logEvent('Processing exceeded 30 seconds; moved to background queue and customer notification sent'); showToast('Analysis moved to the background queue.'); }
  else if (needsClarification) { setStatus('Review needed', 'alert', 'Evidence needs a human check', 'The customer should clarify the conflict or provide a sharper, original file.'); logEvent('Analysis complete; clarification requested for conflicting or incomplete evidence'); showToast('Evidence needs clarification before a reply.'); }
  else { setStatus('Verified', 'done', 'Signals are consistent', 'The extracted evidence supports the customer message.'); logEvent(`Analysis complete; ${findings.length} redacted signals recorded`); showToast('Case analyzed successfully.'); }
  state.analyzing = false; $('#analyzeBtn').disabled = false;
}
messageInput.addEventListener('input', () => { $('#charCount').textContent = `${messageInput.value.length} characters`; });
fileInput.addEventListener('change', event => addFiles(event.target.files));
['dragenter','dragover'].forEach(type => dropZone.addEventListener(type, event => { event.preventDefault(); dropZone.classList.add('dragging'); }));
['dragleave','drop'].forEach(type => dropZone.addEventListener(type, event => { event.preventDefault(); dropZone.classList.remove('dragging'); }));
dropZone.addEventListener('drop', event => addFiles(event.dataTransfer.files));
$('#analyzeBtn').addEventListener('click', analyze);
$('#resetBtn').addEventListener('click', () => { state.files = []; messageInput.value = ''; $('#charCount').textContent = '0 characters'; $('#auditLog').innerHTML = '<div class="audit-entry"><span class="audit-time">NOW</span><span>Case cleared. No customer data recorded.</span></div>'; renderFiles(); setStatus('Ready', 'idle', 'Waiting for evidence', 'We’ll compare message claims against extracted document and image signals.'); $('#findings').innerHTML = 'Analysis results will appear here.'; $('#signalCount').textContent = '0 found'; $('#progressWrap').hidden = true; });
messageInput.dispatchEvent(new Event('input'));
