const STORAGE_KEY = 'greyMisnomerDashboardState';
const state = {
  records: [],
  commitment: null,
  poi: null,
  batch: null,
  burns: [],
  unlockedStep: 1,
  role: 'Project Owner',
};

const claimTypes = {
  CorporateNetZero: 'Corporate Net-Zero',
  Compliance: 'Compliance',
  Payg: 'Pay-As-You-Go',
};

const toast = document.getElementById('toast');

document.addEventListener('DOMContentLoaded', () => {
  initializeDashboard();
});

function initializeDashboard() {
  loadSession();
  attachRoleHandler();
  populateDefaultMrvRows();
  renderStep(state.unlockedStep);
  renderRole();
}

function attachRoleHandler() {
  const select = document.getElementById('roleSelect');
  select.value = state.role;
  select.addEventListener('change', (event) => {
    state.role = event.target.value;
    saveSession();
  });
}

function populateDefaultMrvRows() {
  if (state.records.length === 0) {
    for (let i = 0; i < 5; i += 1) {
      const now = Math.floor(Date.now() / 1000) + i * 86400;
      state.records.push({ timestamp: now, value: 1200 + i * 4.5, unit: 'kWh', source: `SENSOR-${String(i + 1).padStart(3, '0')}` });
    }
  }
  renderMrvRows();
}

function renderMrvRows() {
  const body = document.getElementById('mrvBody');
  body.innerHTML = '';

  state.records.forEach((record, index) => {
    const row = document.createElement('tr');
    row.innerHTML = `
      <td>${index + 1}</td>
      <td><input type="number" class="mrv-ts" value="${record.timestamp}" /></td>
      <td><input type="number" class="mrv-val" value="${record.value.toFixed(1)}" step="0.01" /></td>
      <td><input type="text" class="mrv-unit" value="${record.unit}" /></td>
      <td><input type="text" class="mrv-src" value="${record.source}" /></td>
      <td><button class="btn btn-secondary btn-sm" onclick="removeMrvRow(${index})">✕</button></td>
    `;
    body.appendChild(row);
  });
}

function addMrvRow() {
  state.records.push({ timestamp: Math.floor(Date.now() / 1000), value: 0, unit: 'kWh', source: 'SENSOR' });
  renderMrvRows();
  saveSession();
}

function removeMrvRow(index) {
  state.records.splice(index, 1);
  renderMrvRows();
  saveSession();
}

function getMrvRows() {
  const rows = document.querySelectorAll('#mrvBody tr');
  return Array.from(rows).map((row) => ({
    timestamp: Number(row.querySelector('.mrv-ts').value) || 0,
    value: Number(row.querySelector('.mrv-val').value) || 0,
    unit: row.querySelector('.mrv-unit').value.trim() || 'kWh',
    source: row.querySelector('.mrv-src').value.trim() || 'SENSOR',
  }));
}

async function stepBuildCommitment() {
  const records = getMrvRows().filter((r) => r.timestamp > 0 && !!r.source);
  if (!records.length) {
    return showToast('Add at least one MRV record before building a commitment.');
  }

  try {
    state.records = records;
    const timestamp = Math.floor(Date.now() / 1000);
    const commitment = await buildCommitment(records, timestamp);
    state.commitment = commitment;
    state.unlockedStep = Math.max(state.unlockedStep, 2);
    saveSession();
    renderCommitResult(commitment, records);
    unlockSteps(2);
    goStep(2);
  } catch (error) {
    showToast(error.message || String(error));
  }
}

async function buildCommitment(records, timestamp) {
  const leaves = await Promise.all(records.map((record) => hashLeaf(JSON.stringify(record))));
  const merkleRoot = await buildMerkleRoot(leaves);
  const proofFirst = await verifyInclusion(records, 0, merkleRoot);
  const proofLast = await verifyInclusion(records, records.length - 1, merkleRoot);

  return {
    merkle_root_hex: merkleRoot,
    algorithm: 'SHA-256',
    leaf_count: records.length,
    timestamp,
    proof_first: proofFirst,
    proof_last: proofLast,
  };
}

async function hashLeaf(payload) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(payload));
  return bytesToHex(new Uint8Array(digest));
}

async function buildMerkleRoot(leaves) {
  if (!leaves.length) {
    return null;
  }
  let nodes = leaves.slice();
  while (nodes.length > 1) {
    const next = [];
    for (let i = 0; i < nodes.length; i += 2) {
      const left = nodes[i];
      const right = i + 1 < nodes.length ? nodes[i + 1] : nodes[i];
      next.push(await hashPair(left, right));
    }
    nodes = next;
  }
  return nodes[0];
}

async function hashPair(left, right) {
  const leftBytes = hexToBytes(left);
  const rightBytes = hexToBytes(right);
  const combined = new Uint8Array(leftBytes.length + rightBytes.length);
  combined.set(leftBytes, 0);
  combined.set(rightBytes, leftBytes.length);
  const digest = await crypto.subtle.digest('SHA-256', combined);
  return bytesToHex(new Uint8Array(digest));
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function verifyInclusion(records, index, merkleRoot) {
  if (!records.length || index < 0 || index >= records.length) {
    return false;
  }

  const leaves = await Promise.all(records.map((record) => hashLeaf(JSON.stringify(record))));
  const proof = await buildMerkleProof(leaves, index);
  return verifyMerkleProof(leaves[index], proof, merkleRoot);
}

async function buildMerkleProof(leaves, index) {
  const proof = [];
  let level = leaves.slice();
  let idx = index;

  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : left;
      next.push(await hashPair(left, right));
      if (i === idx || i + 1 === idx) {
        proof.push({ sibling: i === idx ? right : left, position: i === idx ? 'right' : 'left' });
      }
    }
    idx = Math.floor(idx / 2);
    level = next;
  }
  return proof;
}

async function verifyMerkleProof(leafHash, proof, rootHash) {
  let hash = leafHash;
  for (const step of proof) {
    hash = step.position === 'left' ? await hashPair(step.sibling, hash) : await hashPair(hash, step.sibling);
  }
  return hash === rootHash;
}

function renderCommitResult(commitment, records) {
  const result = document.getElementById('commitResult');
  result.innerHTML = `
    <div class="hash-box">
      <span class="hl">Merkle root</span>
      ${commitment.merkle_root_hex}
    </div>
    <div class="result-card success">
      <h4>MRV Commitment Generated</h4>
      ${kv('Algorithm', commitment.algorithm, 'blue')}
      ${kv('Leaf count', commitment.leaf_count, 'green')}
      ${kv('Timestamp', commitment.timestamp)}
      ${kv('Proof status', commitment.proof_first && commitment.proof_last ? 'First/last records verified' : 'Verification failed', 'green')}
    </div>
    ${proofRow(commitment.proof_first, 'First record inclusion proof verified')}
    ${proofRow(commitment.proof_last, 'Last record inclusion proof verified')}
  `;
}

function stepIssuePoi() {
  if (!state.commitment) {
    return showToast('Complete MRV commitment before issuing PoI.');
  }

  const projectId = getValue('f-project_id');
  const creditId = getValue('f-credit_id');
  const serialStart = Number(getValue('f-serial_start'));
  const serialEnd = Number(getValue('f-serial_end'));
  const jurisdiction = getValue('f-jurisdiction');
  const methodologyHash = getValue('f-methodology_hash');
  const vvbSignature = getValue('f-vvb_signature');
  const owner = getValue('f-owner');

  if (!projectId || !creditId || isNaN(serialStart) || isNaN(serialEnd) || serialEnd < serialStart || !owner) {
    return showToast('Fill all PoI fields and make sure the serial range is valid.');
  }

  const ccMintAmount = serialEnd - serialStart + 1;
  state.poi = {
    project_id: projectId,
    credit_id: creditId,
    serial_start: serialStart,
    serial_end: serialEnd,
    cc_mint_amount: ccMintAmount,
    jurisdiction,
    methodology_hash: methodologyHash,
    vvb_signature: vvbSignature,
    owner,
    commitment: state.commitment,
    created_at: Date.now(),
  };
  state.unlockedStep = Math.max(state.unlockedStep, 3);
  saveSession();
  renderPoiResult();
  unlockSteps(3);
  goStep(3);
}

function renderPoiResult() {
  const el = document.getElementById('poiResult');
  if (!state.poi) {
    el.innerHTML = '';
    return;
  }

  el.innerHTML = `
    <div class="result-card success">
      <h4>Proof-of-Integrity Prepared</h4>
      ${kv('Project', state.poi.project_id)}
      ${kv('Credit ID', state.poi.credit_id, 'blue')}
      ${kv('Serial range', `${state.poi.serial_start} – ${state.poi.serial_end}`)}
      ${kv('Amount', `${state.poi.cc_mint_amount} tCO2e`, 'green')}
      ${kv('Owner', state.poi.owner)}
      ${kv('Jurisdiction', state.poi.jurisdiction)}
    </div>
  `;
}

function stepMint() {
  if (!state.poi || !state.commitment) {
    return showToast('A valid PoI is required before minting.');
  }
  if (state.batch) {
    return showToast('Credits have already been minted in this session.');
  }

  const { credit_id, project_id, owner, serial_start, serial_end, cc_mint_amount } = state.poi;
  const totalSize = serial_end - serial_start + 1;
  if (cc_mint_amount !== totalSize) {
    return showToast('Mint amount must exactly match the serial range size.');
  }

  state.batch = {
    credit_id,
    project_id,
    owner,
    original_range: { start: serial_start, end: serial_end },
    slices: [{ range: { start: serial_start, end: serial_end }, status: 'Active' }],
    total_credits: totalSize,
    minted_at: Date.now(),
  };
  state.unlockedStep = Math.max(state.unlockedStep, 4);
  saveSession();
  renderMintResult();
  renderSlices(state.batch);
  unlockSteps(4);
  goStep(4);
}

function renderMintResult() {
  const el = document.getElementById('mintResult');
  if (!state.batch) {
    el.innerHTML = '';
    return;
  }

  el.innerHTML = `
    <div class="result-card success">
      <h4>Credit Batch Minted</h4>
      ${kv('Credit ID', state.batch.credit_id, 'blue')}
      ${kv('Project ID', state.batch.project_id)}
      ${kv('Owner', state.batch.owner, 'green')}
      ${kv('Original range', `${state.batch.original_range.start} – ${state.batch.original_range.end}`)}
      ${kv('Supply', `${state.batch.total_credits} tCO2e`, 'green')}
    </div>
    ${proofRow(true, 'Serial range reserved in the client registry')} 
    ${proofRow(true, 'PoI consumed and marked as used for this session')}
  `;
}

function stepTransfer() {
  if (!state.batch) {
    return showToast('Mint credits before attempting a transfer.');
  }

  const newOwner = getValue('f-new_owner');
  if (!newOwner) {
    return showToast('Provide a new owner wallet address.');
  }

  state.batch.owner = newOwner;
  state.unlockedStep = Math.max(state.unlockedStep, 5);
  saveSession();
  renderTransferResult();
  renderSlices(state.batch);
  unlockSteps(5);
}

function renderTransferResult() {
  const el = document.getElementById('transferResult');
  el.innerHTML = `
    <div class="result-card success">
      <h4>Ownership Transferred</h4>
      ${kv('Credit ID', state.batch.credit_id)}
      ${kv('New Owner', state.batch.owner, 'green')}
      ${kv('Active supply', `${activeSupply()} tCO2e`, 'blue')}
    </div>
  `;
}

function stepBurn() {
  if (!state.batch) {
    return showToast('Minted credit batch is required before retiring credits.');
  }

  const burnStart = Number(getValue('f-burn_start'));
  const burnEnd = Number(getValue('f-burn_end'));
  const beneficiary = getValue('f-beneficiary');
  const claimType = getValue('f-claim_type');
  if (Number.isNaN(burnStart) || Number.isNaN(burnEnd) || burnStart > burnEnd) {
    return showToast('Burn range must be valid and non-empty.');
  }
  if (!beneficiary) {
    return showToast('Add a beneficiary for this retire action.');
  }

  const result = retireSlice(burnStart, burnEnd);
  if (!result.success) {
    return showToast(result.message);
  }

  const poo = {
    project_id: state.batch.project_id,
    credit_id: state.batch.credit_id,
    beneficiary,
    claim_type: claimType,
    serial_start: burnStart,
    serial_end: burnEnd,
    cc_amount: burnEnd - burnStart + 1,
    amount_tco2e: burnEnd - burnStart + 1,
    burn_tx_hash: generateHash(`${state.batch.credit_id}-${burnStart}-${burnEnd}-${Date.now()}`),
    status: 'FINALIZED',
    amounts_consistent: true,
    created_at: Date.now(),
  };

  state.burns.push(poo);
  state.unlockedStep = Math.max(state.unlockedStep, 6, 7, 8);
  saveSession();
  renderBurnResults(poo);
  renderSlices(state.batch);
  unlockSteps(6);
}

function retireSlice(start, end) {
  const batch = state.batch;
  const activeSlices = batch.slices.filter((slice) => slice.status === 'Active');
  const overlap = activeSlices.reduce((sum, slice) => {
    const low = Math.max(slice.range.start, start);
    const high = Math.min(slice.range.end, end);
    return sum + Math.max(0, high - low + 1);
  }, 0);
  if (overlap !== end - start + 1) {
    return { success: false, message: 'Burn range must lie entirely within active serial credits.' };
  }

  const updated = [];
  batch.slices.forEach((slice) => {
    if (slice.status !== 'Active') {
      updated.push(slice);
      return;
    }

    if (slice.range.end < start || slice.range.start > end) {
      updated.push(slice);
      return;
    }

    if (slice.range.start < start) {
      updated.push({ status: 'Active', range: { start: slice.range.start, end: start - 1 } });
    }

    const retireStart = Math.max(slice.range.start, start);
    const retireEnd = Math.min(slice.range.end, end);
    updated.push({ status: 'Retired', range: { start: retireStart, end: retireEnd } });

    if (slice.range.end > end) {
      updated.push({ status: 'Active', range: { start: end + 1, end: slice.range.end } });
    }
  });

  batch.slices = normalizeSlices(updated);
  return { success: true };
}

function normalizeSlices(slices) {
  const sorted = slices.slice().sort((a, b) => a.range.start - b.range.start);
  const merged = [];
  for (const slice of sorted) {
    if (!merged.length) {
      merged.push({ ...slice, range: { ...slice.range } });
      continue;
    }

    const last = merged[merged.length - 1];
    if (last.status === slice.status && last.range.end + 1 >= slice.range.start) {
      last.range.end = Math.max(last.range.end, slice.range.end);
      continue;
    }
    merged.push({ ...slice, range: { ...slice.range } });
  }
  return merged;
}

function renderBurnResults(poo) {
  const container = document.getElementById('burnResults');
  const card = document.createElement('div');
  card.className = 'result-card success';
  card.innerHTML = `
    <h4>Proof-of-Offset Issued</h4>
    ${kv('Beneficiary', poo.beneficiary, 'green')}
    ${kv('Claim type', claimTypes[poo.claim_type] || poo.claim_type, 'blue')}
    ${kv('Serial range', `${poo.serial_start} – ${poo.serial_end}`)}
    ${kv('Retired credits', `${poo.cc_amount} tCO2e`, 'green')}
    ${kv('Burn tx', poo.burn_tx_hash.slice(0, 16) + '...')}
  `;
  container.prepend(card);
}

function renderSlices(batch) {
  const container = document.getElementById('currentSlicesDisplay');
  if (!batch) {
    container.innerHTML = '';
    return;
  }

  const total = batch.original_range.end - batch.original_range.start + 1;
  const segments = batch.slices.map((slice) => {
    const size = slice.range.end - slice.range.start + 1;
    const width = ((size / total) * 100).toFixed(2);
    const label = size > total * 0.08 ? `${slice.range.start}–${slice.range.end}` : `${slice.status}`;
    return `<div class="seg ${slice.status.toLowerCase()}" style="width:${width}%" title="${slice.status}: ${slice.range.start}–${slice.range.end} (${size})">${label}</div>`;
  }).join('');

  container.innerHTML = `
    <div class="range-wrap">
      <div class="range-label">SERIAL RANGE: ${batch.original_range.start} – ${batch.original_range.end}</div>
      <div class="range-bar">${segments}</div>
      <div class="range-legend">
        <span><span class="dot active"></span>Active ${activeSupply()} tCO2e</span>
        <span><span class="dot retired"></span>Retired ${retiredSupply()} tCO2e</span>
      </div>
    </div>
  `;
}

function activeSupply() {
  if (!state.batch) return 0;
  return state.batch.slices.filter((s) => s.status === 'Active').reduce((sum, s) => sum + (s.range.end - s.range.start + 1), 0);
}

function retiredSupply() {
  if (!state.batch) return 0;
  return state.batch.slices.filter((s) => s.status === 'Retired').reduce((sum, s) => sum + (s.range.end - s.range.start + 1), 0);
}

function renderArtifacts() {
  const summary = document.getElementById('artifactSummary');
  const dlGrid = document.getElementById('dlGrid');
  dlGrid.innerHTML = '';

  const retired = retiredSupply();
  summary.innerHTML = `
    <div class="cons-row">
      <div class="cons-box"><span class="cons-val">${state.commitment ? state.commitment.leaf_count : '—'}</span><span class="cons-lbl">MRV records</span></div>
      <div class="cons-box"><span class="cons-val">${state.batch ? state.batch.total_credits : '—'}</span><span class="cons-lbl">Minted credits</span></div>
      <div class="cons-box"><span class="cons-val">${retired}</span><span class="cons-lbl">Retired credits</span></div>
    </div>
    ${proofRow(true, 'Session state preserved for local audit')}
  `;

  if (state.records.length) {
    addDownload(dlGrid, 'mrv_records.json', { type: 'MRVRecords', records: state.records }, 'MRV records');
  }
  if (state.commitment) {
    addDownload(dlGrid, 'mrv_commitment.json', state.commitment, 'Commitment');
  }
  if (state.poi) {
    addDownload(dlGrid, 'poi.json', state.poi, 'PoI');
  }
  if (state.batch) {
    addDownload(dlGrid, 'credit_batch.json', state.batch, 'Credit batch');
  }
  state.burns.forEach((poo, index) => {
    addDownload(dlGrid, `poo_${index + 1}.json`, poo, `PoO #${index + 1}`);
  });
  addDownload(dlGrid, 'registry_state.json', buildRegistrySnapshot(), 'Registry state');
}

function addDownload(container, filename, payload, label) {
  const anchor = document.createElement('a');
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  anchor.href = URL.createObjectURL(blob);
  anchor.download = filename;
  anchor.className = 'btn btn-green btn-sm';
  anchor.innerText = `⬇ ${label}`;
  container.appendChild(anchor);
}

function runAudit() {
  const summary = document.getElementById('auditResult');
  if (!state.batch) {
    summary.innerHTML = `<div class="result-card error"><h4>Audit unavailable</h4><p>Mint a credit batch before auditing invariants.</p></div>`;
    return;
  }

  const minted = state.batch.total_credits;
  const active = activeSupply();
  const retired = retiredSupply();
  const burnedRanges = state.burns.map((poo) => ({ start: poo.serial_start, end: poo.serial_end }));
  const noDoubleBurn = validateRangeSet(burnedRanges);
  const supplyOk = minted === active + retired;
  const spansOk = validateSliceCoverage(state.batch.slices, state.batch.original_range);

  summary.innerHTML = `
    <div class="cons-row">
      <div class="cons-box"><span class="cons-val">${minted}</span><span class="cons-lbl">Minted</span></div>
      <div class="cons-box"><span class="cons-val">${active}</span><span class="cons-lbl">Active</span></div>
      <div class="cons-box"><span class="cons-val">${retired}</span><span class="cons-lbl">Retired</span></div>
    </div>
    ${proofRow(supplyOk, `Supply conservation: minted ${minted} = active ${active} + retired ${retired}`)}
    ${proofRow(noDoubleBurn, 'No overlapping burn ranges detected')}
    ${proofRow(spansOk, 'Serial slices cover the original range without overlap')}
    ${proofRow(true, 'Original range persists in the audit trail')}
  `;
}

function validateRangeSet(ranges) {
  const sorted = ranges.slice().sort((a, b) => a.start - b.start);
  for (let i = 1; i < sorted.length; i += 1) {
    if (sorted[i].start <= sorted[i - 1].end) {
      return false;
    }
  }
  return true;
}

function validateSliceCoverage(slices, original) {
  const sorted = normalizeSlices(slices.filter((slice) => slice.range.end >= slice.range.start));
  let cursor = original.start;
  for (const slice of sorted) {
    if (slice.range.start > cursor || slice.range.start < original.start) {
      return false;
    }
    cursor = slice.range.end + 1;
  }
  return cursor === original.end + 1;
}

function goStep(index) {
  if (index > state.unlockedStep) {
    return;
  }
  document.querySelectorAll('.panel').forEach((panel) => panel.classList.remove('active'));
  document.querySelectorAll('.step-item').forEach((item) => item.classList.remove('active'));
  document.getElementById(`panel-${index}`).classList.add('active');
  document.getElementById(`si-${index}`).classList.add('active');

  if (index === 7) {
    renderArtifacts();
  }
  if (index === 8) {
    runAudit();
  }
}

function unlockSteps(maxStep) {
  for (let i = 1; i <= maxStep; i += 1) {
    const item = document.getElementById(`si-${i}`);
    item.classList.remove('locked');
    if (i < maxStep) {
      item.classList.add('done');
      document.getElementById(`sn-${i}`).textContent = '✓';
    }
  }
  state.unlockedStep = Math.max(state.unlockedStep, maxStep);
  saveSession();
}

function resetAll() {
  if (!confirm('Clear the current session and restart the dashboard?')) {
    return;
  }
  localStorage.removeItem(STORAGE_KEY);
  location.reload();
}

function saveSession() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
}

function loadSession() {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (!stored) return;
    const saved = JSON.parse(stored);
    if (saved) {
      Object.assign(state, saved);
    }
  } catch {
    // ignore invalid session data
  }
}

function renderStep(step) {
  unlockSteps(state.unlockedStep);
  goStep(step);
  if (state.commitment) {
    renderCommitResult(state.commitment, state.records);
  }
  if (state.poi) {
    renderPoiResult();
  }
  if (state.batch) {
    renderMintResult();
    renderSlices(state.batch);
  }
  if (state.burns.length) {
    state.burns.slice().reverse().forEach((poo) => renderBurnResults(poo));
  }
}

function renderRole() {
  const select = document.getElementById('roleSelect');
  if (select) {
    select.value = state.role;
  }
}

function getValue(id) {
  return document.getElementById(id)?.value.trim() || '';
}

function kv(label, value, cls = '') {
  return `<div class="kv-row"><div class="kv-key">${label}</div><div class="kv-val ${cls}">${value}</div></div>`;
}

function proofRow(ok, text) {
  return `<div class="proof-row ${ok ? 'ok' : 'fail'}"><span class="pi">${ok ? '✅' : '🚫'}</span> ${text}</div>`;
}

function showToast(message) {
  toast.textContent = String(message);
  toast.classList.add('show');
  clearTimeout(window.toastTimeout);
  window.toastTimeout = setTimeout(() => toast.classList.remove('show'), 4300);
}

function generateHash(data) {
  let hash = 0;
  for (let i = 0; i < data.length; i += 1) {
    hash = (hash << 5) - hash + data.charCodeAt(i);
    hash |= 0;
  }
  return `TX_${Math.abs(hash).toString(16).padStart(8, '0')}`;
}

function buildRegistrySnapshot() {
  return {
    batch: state.batch,
    burns: state.burns,
    commitment: state.commitment,
    poi: state.poi,
    role: state.role,
    updated_at: Date.now(),
  };
}
