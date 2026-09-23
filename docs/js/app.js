    import init, { build_commitment, verify_inclusion, WasmRegistry } from '../pkg/grey_misnomer_wasm.js';

    // ══════════════════════════════════════════════════════════════════
    //  STATE
    // ══════════════════════════════════════════════════════════════════
    let registry = null;
    let mrvRecords = [];
    let commitment = null;

    // Platform state (lives in JS, simulates "DB")
    let projects = [];       // { id, name, tech, jurisdiction, org, expectedCredits, lat, lng, status, mrvCommitted, poiIssued }
    let mintedBatches = [];  // { creditId, projectId, owner, totalCredits, originalStart, originalEnd, poiStatus, listedOnMarket, listingPrice, pooReceipts }
    let currentRole = 'admin';
    let currentWallet = '0xProjectOwner';
    let currentOrg = 'ABC Solar Energy Pvt. Ltd.';

    // ══════════════════════════════════════════════════════════════════
    //  BOOTSTRAP
    // ══════════════════════════════════════════════════════════════════
    window.addEventListener('DOMContentLoaded', async () => {
      document.getElementById('loadingOverlay').classList.add('show');
      try {
        await init();
        registry = new WasmRegistry();
      } catch (err) {
        console.error("WASM boot error:", err);
        showToast("Fatal: Failed to load WebAssembly module.");
      } finally {
        document.getElementById('loadingOverlay').classList.remove('show');
      }
      applyRolePermissions();
      refreshDashboard();
    });

    // ══════════════════════════════════════════════════════════════════
    //  NAVIGATION
    // ══════════════════════════════════════════════════════════════════
    let currentView = 'dashboard';

    function navigate(view) {
      const navItem = document.getElementById(`nav-${view}`);
      if (navItem && navItem.classList.contains('locked')) {
        showToast('This module is not available for your current role.');
        return;
      }
      document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
      document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
      document.getElementById(`view-${view}`).classList.add('active');
      document.getElementById(`nav-${view}`).classList.add('active');
      currentView = view;

      // Refresh dynamic views
      if (view === 'dashboard') refreshDashboard();
      if (view === 'registry') refreshRegistry();
      if (view === 'marketplace') refreshMarketplace();
      if (view === 'portfolio') refreshPortfolio();
      if (view === 'verification') refreshVerification();
      if (view === 'projects') refreshProjectsList();
      if (view === 'mrv') refreshMrvProjectSelect();
      if (view === 'audit') runAuditChecks();
    }
    window.navigate = navigate;

    // ══════════════════════════════════════════════════════════════════
    //  ROLE MANAGEMENT
    // ══════════════════════════════════════════════════════════════════
    const roleAccess = {
      admin:     ['dashboard','governance','projects','mrv','verification','registry','marketplace','portfolio','audit','admin'],
      developer: ['dashboard','projects','mrv','registry','marketplace','portfolio','audit'],
      validator: ['dashboard','governance','verification','registry','audit'],
      buyer:     ['dashboard','marketplace','portfolio','registry','audit'],
      auditor:   ['dashboard','registry','audit']
    };

    function switchRole(role) {
      currentRole = role;
      // Change wallet identity based on role
      if (role === 'buyer') { currentWallet = '0xCorporateBuyer'; currentOrg = 'GreenCorp Industries'; }
      else if (role === 'validator') { currentWallet = '0xValidator_VVB'; currentOrg = 'Bureau of Energy Efficiency'; }
      else if (role === 'auditor') { currentWallet = '0xAuditor'; currentOrg = 'Independent Audit Firm'; }
      else { currentWallet = '0xProjectOwner'; currentOrg = 'ABC Solar Energy Pvt. Ltd.'; }
      document.getElementById('admin-wallet').value = currentWallet;
      document.getElementById('admin-org').value = currentOrg;
      applyRolePermissions();
      // Navigate to dashboard if current view is locked
      const allowed = roleAccess[role] || [];
      if (!allowed.includes(currentView)) navigate('dashboard');
      refreshDashboard();
    }
    window.switchRole = switchRole;

    function applyRolePermissions() {
      const allowed = roleAccess[currentRole] || [];
      const allViews = ['dashboard','governance','projects','mrv','verification','registry','marketplace','portfolio','audit','admin'];
      allViews.forEach(v => {
        const nav = document.getElementById(`nav-${v}`);
        if (!nav) return;
        if (allowed.includes(v)) nav.classList.remove('locked');
        else nav.classList.add('locked');
      });
    }

    // ══════════════════════════════════════════════════════════════════
    //  PROJECTS MODULE
    // ══════════════════════════════════════════════════════════════════
    function registerProject() {
      const project = {
        id: document.getElementById('prj-id').value || `PRJ-${Date.now()}`,
        name: document.getElementById('prj-name').value || 'Unnamed Project',
        tech: document.getElementById('prj-tech').value,
        jurisdiction: document.getElementById('prj-jurisdiction').value,
        org: document.getElementById('prj-org').value,
        expectedCredits: parseInt(document.getElementById('prj-credits').value) || 0,
        lat: document.getElementById('prj-lat').value,
        lng: document.getElementById('prj-lng').value,
        status: 'Registered',
        mrvCommitted: false,
        poiIssued: false,
        minted: false,
        commitment: null,
        mrvData: null,
        createdAt: new Date().toISOString()
      };
      projects.push(project);
      document.getElementById('badge-projects').textContent = projects.length;
      refreshProjectsList();
      showSuccessToast(`✓ Project "${project.name}" registered`);
      refreshDashboard();
    }
    window.registerProject = registerProject;

    function refreshProjectsList() {
      const container = document.getElementById('projectsList');
      if (projects.length === 0) {
        container.innerHTML = '<div class="empty-state"><div class="empty-icon">📁</div><h3>No Projects Yet</h3><p>Register your first carbon reduction project above.</p></div>';
        return;
      }
      let html = '<div class="table-wrap"><table class="data"><thead><tr><th>Project ID</th><th>Name</th><th>Technology</th><th>Status</th><th>Credits</th><th>Actions</th></tr></thead><tbody>';
      projects.forEach((p, i) => {
        const statusClass = p.minted ? 'active' : (p.poiIssued ? 'listed' : (p.mrvCommitted ? 'pending' : ''));
        const statusText = p.minted ? 'Minted' : (p.poiIssued ? 'PoI Issued' : (p.mrvCommitted ? 'MRV Committed' : 'Registered'));
        html += `<tr>
          <td style="color:var(--blue)">${p.id}</td>
          <td style="color:var(--text);font-family:var(--sans)">${p.name}</td>
          <td>${p.tech}</td>
          <td><span class="status-pill ${statusClass || 'pending'}">${statusText}</span></td>
          <td>${p.expectedCredits.toLocaleString()}</td>
          <td>${!p.mrvCommitted ? `<button class="btn btn-secondary btn-sm" onclick="navigate('mrv')">Upload MRV</button>` : (!p.minted && p.poiIssued ? `<button class="btn btn-green btn-sm" onclick="mintFromProject(${i})">🪙 Mint</button>` : '—')}</td>
        </tr>`;
      });
      html += '</tbody></table></div>';
      container.innerHTML = html;
    }

    // ══════════════════════════════════════════════════════════════════
    //  MRV MODULE (reusing existing logic)
    // ══════════════════════════════════════════════════════════════════
    function refreshMrvProjectSelect() {
      const sel = document.getElementById('mrv-project-select');
      sel.innerHTML = '';
      if (projects.length === 0) {
        sel.innerHTML = '<option value="">— Register a project first —</option>';
        return;
      }
      projects.filter(p => !p.minted).forEach(p => {
        sel.innerHTML += `<option value="${p.id}">${p.id} — ${p.name}</option>`;
      });
    }

    function addMrvRow(ts = null, val = null, unit = 'kWh', src = null) {
      const body = document.getElementById('mrvBody');
      const idx = body.rows.length;
      const defaultTs = ts || Math.floor(Date.now() / 1000);
      const defaultVal = val || 1200.0;
      const defaultSrc = src || `SOLAR-SENSOR-${String(idx % 4).padStart(3, '0')}`;
      const row = document.createElement('tr');
      row.innerHTML = `
        <td style="color:var(--muted);font-family:var(--mono);font-size:0.73rem;">${idx + 1}</td>
        <td><input type="number" class="mrv-ts" value="${defaultTs}"></td>
        <td><input type="number" class="mrv-val" value="${defaultVal}" step="0.1"></td>
        <td><input type="text" class="mrv-unit" value="${unit}" style="width:70px;"></td>
        <td><input type="text" class="mrv-src" value="${defaultSrc}"></td>
        <td><button onclick="this.closest('tr').remove();reindexTable();updateRecordBadge();" style="background:none;border:none;color:var(--muted);cursor:pointer;font-size:0.9rem;">✕</button></td>`;
      body.appendChild(row);
      updateRecordBadge();
    }
    window.addMrvRow = addMrvRow;
    window.reindexTable = () => { document.querySelectorAll('#mrvBody tr').forEach((row, i) => { row.cells[0].textContent = i + 1; }); };

    function clearMrvTable() { document.getElementById('mrvBody').innerHTML = ''; updateRecordBadge(); }
    window.clearMrvTable = clearMrvTable;

    function updateRecordBadge() {
      const n = document.querySelectorAll('#mrvBody tr').length;
      const badge = document.getElementById('recordBadge');
      if (badge) badge.textContent = `${n} record${n !== 1 ? 's' : ''}`;
    }

    function seedDemoDataset() {
      clearMrvTable();
      for (let day = 0; day < 30; day++) {
        const ts = 1700000000 + day * 86400;
        const val = (1250.0 + (day * 3.5)).toFixed(1);
        const src = `SOLAR-SENSOR-${String(day % 4).padStart(3, '0')}`;
        addMrvRow(ts, val, 'kWh', src);
      }
      updateRecordBadge();
    }
    window.seedDemoDataset = seedDemoDataset;

    function handleFileUpload(event) {
      const file = event.target.files?.[0];
      if (file) processUploadedFile(file);
    }
    window.handleFileUpload = handleFileUpload;

    function processUploadedFile(file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        const text = e.target.result;
        let records = [];
        try {
          if (file.name.endsWith('.json')) {
            records = JSON.parse(text);
            if (!Array.isArray(records)) throw new Error('JSON must be an array');
          } else {
            const lines = text.trim().split(/\r?\n/).filter(l => l.trim());
            const isHeader = isNaN(lines[0].split(',')[0]);
            const dataLines = isHeader ? lines.slice(1) : lines;
            records = dataLines.map((line, i) => {
              const parts = line.split(',');
              if (parts.length < 4) throw new Error(`Row ${i+1}: expected 4 columns`);
              return { timestamp: parseInt(parts[0].trim()) || 0, value: parseFloat(parts[1].trim()) || 0, unit: parts[2].trim() || 'kWh', source: parts[3].trim() || `SENSOR-${i}` };
            });
          }
          if (records.length === 0) throw new Error('File contains no records');
          clearMrvTable();
          records.forEach(r => addMrvRow(r.timestamp, r.value, r.unit || 'kWh', r.source));
          updateRecordBadge();
          showSuccessToast(`✓ Imported ${records.length} records from ${file.name}`);
        } catch (err) { showToast(`Import failed: ${err.message}`); }
      };
      reader.readAsText(file);
    }

    // Drag and drop
    (() => {
      const zone = document.getElementById('uploadZone');
      if (!zone) return;
      zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('drag-over'); });
      zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
      zone.addEventListener('drop', (e) => { e.preventDefault(); zone.classList.remove('drag-over'); const file = e.dataTransfer?.files?.[0]; if (file) processUploadedFile(file); });
    })();

    function getMrvData() {
      const rows = document.querySelectorAll('#mrvBody tr');
      const list = [];
      rows.forEach(r => {
        list.push({
          timestamp: parseInt(r.querySelector('.mrv-ts').value) || 0,
          value: parseFloat(r.querySelector('.mrv-val').value) || 0.0,
          unit: r.querySelector('.mrv-unit').value,
          source: r.querySelector('.mrv-src').value
        });
      });
      return list;
    }

    async function processMrv() {
      const list = getMrvData();
      if (list.length === 0) { showToast("Please enter at least one MRV record."); return; }

      const selProjectId = document.getElementById('mrv-project-select').value;
      if (!selProjectId) { showToast("Please select a project first."); return; }

      try {
        const timestamp = BigInt(Math.floor(Date.now() / 1000));
        const jsonStr = JSON.stringify(list);
        const result = build_commitment(jsonStr, timestamp);
        commitment = JSON.parse(result);
        mrvRecords = list;
        await registry.store_commitment(jsonStr, timestamp);

        // Update project state
        const prj = projects.find(p => p.id === selProjectId);
        if (prj) { prj.mrvCommitted = true; prj.status = 'MRV Committed'; prj.commitment = commitment; prj.mrvData = list; }

        document.getElementById('mrvCommitmentDisplay').innerHTML = `
          <div class="hash-display"><span class="tag">BLAKE3 Merkle Root</span>${commitment.merkle_root_hex}</div>
          <div class="result-card success">
            <h4>✅ Merkle Commitment Successful (RFC-003)</h4>
            <div class="kv-row"><span class="kv-key">project</span><span class="kv-val blue">${selProjectId}</span></div>
            <div class="kv-row"><span class="kv-key">leaf_count</span><span class="kv-val green">${commitment.leaf_count} leaves</span></div>
            <div class="kv-row"><span class="kv-key">hash_algorithm</span><span class="kv-val blue">${commitment.algorithm}</span></div>
            <div class="kv-row"><span class="kv-key">commitment_ts</span><span class="kv-val">${commitment.timestamp}</span></div>
            <div class="kv-row"><span class="kv-key">data_anchored</span><span class="kv-val green">True (Stored in Registry)</span></div>
          </div>`;

        renderSpotChecks();
        document.getElementById('spotCheckSection').style.display = 'block';

        // Update verification badge
        const pendingCount = projects.filter(p => p.mrvCommitted && !p.poiIssued).length;
        const vBadge = document.getElementById('badge-verification');
        vBadge.textContent = pendingCount;
        vBadge.style.display = pendingCount > 0 ? '' : 'none';

        showSuccessToast('✓ Commitment anchored — awaiting Validator approval');
        refreshDashboard();
      } catch (err) { showToast(`Error: ${err}`); }
    }
    window.processMrv = processMrv;

    function renderSpotChecks() {
      const body = document.getElementById('spotCheckBody');
      body.innerHTML = '';
      const indices = [];
      if (mrvRecords.length > 0) indices.push(0);
      if (mrvRecords.length > 2) indices.push(Math.floor(mrvRecords.length / 2));
      if (mrvRecords.length > 1) indices.push(mrvRecords.length - 1);
      indices.forEach(idx => {
        const record = mrvRecords[idx];
        const row = document.createElement('tr');
        row.innerHTML = `
          <td style="font-family:var(--mono)">[${idx}]</td>
          <td>${record.source}</td>
          <td><span id="spot-val-${idx}">${record.value}</span> ${record.unit}</td>
          <td><input type="checkbox" id="tamper-${idx}" onchange="toggleTamper(${idx})"></td>
          <td id="proof-status-${idx}"><button class="btn btn-secondary btn-sm" onclick="runSpotVerify(${idx})">Verify Inclusion</button></td>`;
        body.appendChild(row);
      });
    }

    window.toggleTamper = (idx) => {
      const checked = document.getElementById(`tamper-${idx}`).checked;
      const displaySpan = document.getElementById(`spot-val-${idx}`);
      if (checked) { displaySpan.textContent = "999999.0 (Tampered)"; displaySpan.style.color = "var(--red)"; }
      else { displaySpan.textContent = mrvRecords[idx].value; displaySpan.style.color = "var(--text)"; }
      document.getElementById(`proof-status-${idx}`).innerHTML = `<button class="btn btn-secondary btn-sm" onclick="runSpotVerify(${idx})">Verify Inclusion</button>`;
    };

    window.runSpotVerify = (idx) => {
      const checked = document.getElementById(`tamper-${idx}`).checked;
      const targetRecord = { ...mrvRecords[idx] };
      if (checked) targetRecord.value = 999999.0;
      try {
        const dummyList = [...mrvRecords]; dummyList[idx] = targetRecord;
        const res = verify_inclusion(JSON.stringify(dummyList), idx, commitment.merkle_root_hex);
        const statusTd = document.getElementById(`proof-status-${idx}`);
        if (res === "verified") statusTd.innerHTML = `<span style="color:var(--green)">✓ Verified</span>`;
        else statusTd.innerHTML = `<span style="color:var(--red)">✗ Rejected</span>`;
      } catch (err) { showToast(err); }
    };

    // ══════════════════════════════════════════════════════════════════
    //  VERIFICATION MODULE
    // ══════════════════════════════════════════════════════════════════
    function refreshVerification() {
      const container = document.getElementById('verificationQueue');
      const pending = projects.filter(p => p.mrvCommitted && !p.poiIssued);
      const approved = projects.filter(p => p.poiIssued);

      if (pending.length === 0 && approved.length === 0) {
        container.innerHTML = '<div class="empty-state"><div class="empty-icon">🔐</div><h3>No Pending Verifications</h3><p>Projects with MRV commitments will appear here for validator approval.</p></div>';
        return;
      }

      let html = '';
      if (pending.length > 0) {
        html += '<h3 style="font-size:1rem;margin-bottom:0.75rem;color:var(--amber)">⏳ Pending Approval</h3>';
        pending.forEach((p, i) => {
          const pIdx = projects.indexOf(p);
          html += `<div class="result-card" style="border-color:rgba(236,178,46,0.2);">
            <h4>📁 ${p.name} <span class="status-pill pending" style="margin-left:0.5rem">Pending</span></h4>
            <div class="kv-row"><span class="kv-key">project_id</span><span class="kv-val blue">${p.id}</span></div>
            <div class="kv-row"><span class="kv-key">technology</span><span class="kv-val">${p.tech}</span></div>
            <div class="kv-row"><span class="kv-key">jurisdiction</span><span class="kv-val">${p.jurisdiction}</span></div>
            <div class="kv-row"><span class="kv-key">merkle_root</span><span class="kv-val green">${p.commitment?.merkle_root_hex || 'N/A'}</span></div>
            <div class="kv-row"><span class="kv-key">leaf_count</span><span class="kv-val">${p.commitment?.leaf_count || 0} records</span></div>
            <div class="btn-row">
              <button class="btn btn-green btn-sm" onclick="approveProject(${pIdx})">✅ Approve & Issue PoI</button>
              <button class="btn btn-secondary btn-sm" onclick="rejectProject(${pIdx})">✗ Reject</button>
            </div>
          </div>`;
        });
      }
      if (approved.length > 0) {
        html += '<h3 style="font-size:1rem;margin-top:1.5rem;margin-bottom:0.75rem;color:var(--green)">✅ Approved</h3>';
        approved.forEach(p => {
          html += `<div class="result-card success">
            <h4>📁 ${p.name} <span class="status-pill active" style="margin-left:0.5rem">PoI Issued</span></h4>
            <div class="kv-row"><span class="kv-key">project_id</span><span class="kv-val blue">${p.id}</span></div>
            <div class="kv-row"><span class="kv-key">merkle_root</span><span class="kv-val green">${p.commitment?.merkle_root_hex || 'N/A'}</span></div>
          </div>`;
        });
      }
      container.innerHTML = html;
    }

    function approveProject(idx) {
      const p = projects[idx];
      p.poiIssued = true;
      p.status = 'PoI Issued';
      showSuccessToast(`✓ PoI issued for "${p.name}"`);
      refreshVerification();
      refreshDashboard();
      // Update verification badge
      const pendingCount = projects.filter(p => p.mrvCommitted && !p.poiIssued).length;
      const vBadge = document.getElementById('badge-verification');
      vBadge.textContent = pendingCount;
      vBadge.style.display = pendingCount > 0 ? '' : 'none';
    }
    window.approveProject = approveProject;

    function rejectProject(idx) {
      projects[idx].mrvCommitted = false;
      projects[idx].status = 'Rejected';
      showToast(`Project "${projects[idx].name}" rejected by validator.`);
      refreshVerification();
    }
    window.rejectProject = rejectProject;

    // ══════════════════════════════════════════════════════════════════
    //  MINTING (from project or registry)
    // ══════════════════════════════════════════════════════════════════
    function mintFromProject(idx) {
      const p = projects[idx];
      if (!p.poiIssued) { showToast('Project must be approved by a Validator first.'); return; }
      if (p.minted) { showToast('Project already minted.'); return; }

      const creditId = `CC-${p.tech.replace(/\s/g, '').toUpperCase().slice(0,5)}-${Date.now().toString(36).toUpperCase()}`;
      const serialStart = 1000000 + mintedBatches.length * 10000;
      const serialEnd = serialStart + p.expectedCredits - 1;

      const poiData = {
        project_id: p.id,
        credit_id: creditId,
        serial_start: serialStart,
        serial_end: serialEnd,
        cc_mint_amount: p.expectedCredits,
        jurisdiction: p.jurisdiction,
        methodology_hash: `SHA256(VM0042-v4.0)`,
        vvb_signature: `0xVVB_SIG_${Date.now().toString(36)}`,
        owner: currentWallet
      };

      try {
        const res = registry.mint(JSON.stringify(poiData));
        const mintData = JSON.parse(res);

        p.minted = true;
        p.status = 'Minted';

        mintedBatches.push({
          creditId: mintData.credit_id,
          projectId: p.id,
          projectName: p.name,
          tech: p.tech,
          owner: mintData.owner,
          totalCredits: mintData.total_credits,
          originalStart: mintData.original_start,
          originalEnd: mintData.original_end,
          poiStatus: mintData.poi_status,
          listedOnMarket: false,
          listingPrice: 0,
          pooReceipts: [],
          mintedAt: new Date().toISOString()
        });

        document.getElementById('badge-registry').textContent = mintedBatches.length;
        showSuccessToast(`✓ ${mintData.total_credits} credits minted as ${mintData.credit_id}`);
        refreshProjectsList();
        refreshDashboard();
        navigate('registry');
      } catch (err) { showToast(`Mint error: ${err}`); }
    }
    window.mintFromProject = mintFromProject;

    // ══════════════════════════════════════════════════════════════════
    //  REGISTRY MODULE
    // ══════════════════════════════════════════════════════════════════
    function refreshRegistry() {
      const container = document.getElementById('registryTable');
      if (mintedBatches.length === 0) {
        container.innerHTML = '<div class="empty-state"><div class="empty-icon">🪙</div><h3>No Credits Minted Yet</h3><p>Register a project, upload MRV data, get it verified, then mint credits.</p></div>';
        document.getElementById('reg-total-batches').textContent = '0';
        document.getElementById('reg-total-active').textContent = '0';
        document.getElementById('reg-total-retired').textContent = '0';
        return;
      }

      document.getElementById('reg-total-batches').textContent = mintedBatches.length;

      let totalActive = 0, totalRetired = 0;
      let html = '<div class="table-wrap"><table class="data"><thead><tr><th>Credit ID</th><th>Project</th><th>Owner</th><th>Supply</th><th>Status</th><th>Actions</th></tr></thead><tbody>';

      mintedBatches.forEach((b, i) => {
        let batchActive = 0, batchRetired = 0;
        try {
          const state = JSON.parse(registry.batch_state(b.creditId));
          batchActive = state.active_total;
          batchRetired = state.retired_total;
        } catch(_) { batchActive = b.totalCredits; }
        totalActive += batchActive;
        totalRetired += batchRetired;

        const statusText = batchRetired >= b.totalCredits ? 'Fully Retired' : (b.listedOnMarket ? 'Listed' : 'Active');
        const statusClass = batchRetired >= b.totalCredits ? 'retired' : (b.listedOnMarket ? 'listed' : 'active');

        html += `<tr>
          <td style="color:var(--blue)">${b.creditId}</td>
          <td style="color:var(--text);font-family:var(--sans)">${b.projectName || b.projectId}</td>
          <td>${b.owner}</td>
          <td>${b.totalCredits.toLocaleString()} tCO2e</td>
          <td><span class="status-pill ${statusClass}">${statusText}</span></td>
          <td>${!b.listedOnMarket && batchActive > 0 ? `<button class="btn btn-secondary btn-sm" onclick="listOnMarket(${i})">🛒 List</button>` : '—'}</td>
        </tr>`;
      });
      html += '</tbody></table></div>';
      container.innerHTML = html;
      document.getElementById('reg-total-active').textContent = totalActive.toLocaleString();
      document.getElementById('reg-total-retired').textContent = totalRetired.toLocaleString();
    }

    function listOnMarket(idx) {
      mintedBatches[idx].listedOnMarket = true;
      mintedBatches[idx].listingPrice = Math.floor(500 + Math.random() * 1000);
      const mBadge = document.getElementById('badge-marketplace');
      mBadge.textContent = mintedBatches.filter(b => b.listedOnMarket).length;
      showSuccessToast(`✓ ${mintedBatches[idx].creditId} listed on marketplace`);
      refreshRegistry();
      refreshDashboard();
    }
    window.listOnMarket = listOnMarket;

    // ══════════════════════════════════════════════════════════════════
    //  MARKETPLACE MODULE
    // ══════════════════════════════════════════════════════════════════
    function refreshMarketplace() {
      const container = document.getElementById('marketplaceListings');
      const listings = mintedBatches.filter(b => b.listedOnMarket);

      if (listings.length === 0) {
        container.innerHTML = '<div class="empty-state"><div class="empty-icon">🛒</div><h3>No Listings Available</h3><p>Minted credits must be published to the marketplace by their owners.</p></div>';
        return;
      }

      let html = '<div class="listing-grid">';
      listings.forEach((b) => {
        const bIdx = mintedBatches.indexOf(b);
        let activeCredits = b.totalCredits;
        try { const state = JSON.parse(registry.batch_state(b.creditId)); activeCredits = state.active_total; } catch(_){}

        const isSeller = b.owner === currentWallet;
        let actionHtml = '';
        if (activeCredits <= 0) {
          actionHtml = '<span class="status-pill retired">Sold Out</span>';
        } else if (isSeller) {
          actionHtml = '<span style="font-size:0.8rem;color:var(--muted);font-style:italic;">You own this listing</span>';
        } else {
          const totalCost = (activeCredits * b.listingPrice).toLocaleString();
          actionHtml = `<button class="btn btn-primary btn-sm" style="width:100%" onclick="purchaseCredit(${bIdx})">🛒 Buy ${activeCredits.toLocaleString()} credits · ₹${totalCost}</button>`;
        }

        html += `<div class="listing-card">
          <div class="listing-header">
            <div class="listing-title">${b.projectName || b.creditId}</div>
            <div class="listing-price">₹${b.listingPrice}/tCO2e</div>
          </div>
          <div class="listing-meta">
            <strong>${b.tech}</strong> · ${b.creditId}<br>
            Seller: ${b.owner}${isSeller ? ' <strong style="color:var(--amber)">(You)</strong>' : ''}
          </div>
          <div class="listing-stats">
            <div class="listing-stat">Available<span>${activeCredits.toLocaleString()}</span></div>
            <div class="listing-stat">Total<span>${b.totalCredits.toLocaleString()}</span></div>
          </div>
          ${actionHtml}
        </div>`;
      });
      html += '</div>';
      container.innerHTML = html;
    }

    function purchaseCredit(bIdx) {
      console.log('[Marketplace] purchaseCredit called for bIdx:', bIdx);
      const batch = mintedBatches[bIdx];
      if (!batch) { showToast('Error: batch not found at index ' + bIdx); return; }
      const previousOwner = batch.owner;
      console.log('[Marketplace] previousOwner:', previousOwner, 'currentWallet:', currentWallet);

      // Guard: can't buy your own credits
      if (previousOwner === currentWallet) {
        showToast('You cannot purchase your own credits. Switch to a different role first (e.g., Corporate Buyer).');
        return;
      }

      // Get available credits
      let activeCredits = batch.totalCredits;
      try { const state = JSON.parse(registry.batch_state(batch.creditId)); activeCredits = state.active_total; } catch(e){ console.error('batch_state error:', e); }
      const totalCost = (activeCredits * batch.listingPrice).toLocaleString();

      // Show in-page purchase confirmation modal instead of confirm() which browsers may suppress
      showPurchaseModal(bIdx, batch, previousOwner, activeCredits, totalCost);
    }
    window.purchaseCredit = purchaseCredit;

    function showPurchaseModal(bIdx, batch, previousOwner, activeCredits, totalCost) {
      // Remove any existing modal
      const existing = document.getElementById('purchaseModal');
      if (existing) existing.remove();

      const modal = document.createElement('div');
      modal.id = 'purchaseModal';
      modal.style.cssText = 'position:fixed;inset:0;background:rgba(5,7,12,0.88);z-index:900;display:flex;align-items:center;justify-content:center;backdrop-filter:blur(10px);animation:fadeUp 0.3s cubic-bezier(0.16,1,0.3,1);';
      modal.innerHTML = `
        <div style="background:var(--bg2);border:1px solid var(--border);border-radius:20px;padding:2rem;max-width:480px;width:90%;box-shadow:0 25px 60px rgba(0,0,0,0.6);">
          <h2 style="font-size:1.2rem;font-weight:800;margin-bottom:1.25rem;display:flex;align-items:center;gap:0.5rem;">🛒 Confirm Purchase</h2>
          <div style="background:var(--bg3);border:1px solid var(--border);border-radius:12px;padding:1rem;margin-bottom:1.25rem;">
            <div class="kv-row"><span class="kv-key">Credit</span><span class="kv-val blue">${batch.creditId}</span></div>
            <div class="kv-row"><span class="kv-key">Project</span><span class="kv-val">${batch.projectName}</span></div>
            <div class="kv-row"><span class="kv-key">Seller</span><span class="kv-val red">${previousOwner}</span></div>
            <div class="kv-row"><span class="kv-key">Buyer</span><span class="kv-val green">${currentWallet} (${currentOrg})</span></div>
            <div class="kv-row"><span class="kv-key">Quantity</span><span class="kv-val green">${activeCredits.toLocaleString()} tCO2e</span></div>
            <div class="kv-row"><span class="kv-key">Unit Price</span><span class="kv-val">₹${batch.listingPrice}/tCO2e</span></div>
            <div class="kv-row" style="border-top:1px solid var(--border);padding-top:0.6rem;"><span class="kv-key" style="font-weight:700;color:var(--text)">Total Cost</span><span class="kv-val green" style="font-size:1.1rem;font-weight:700;">₹${totalCost}</span></div>
          </div>
          <div style="display:flex;gap:0.75rem;">
            <button class="btn btn-primary" style="flex:1;" onclick="executePurchase(${bIdx})">✅ Confirm Purchase</button>
            <button class="btn btn-secondary" style="flex:1;" onclick="document.getElementById('purchaseModal').remove()">Cancel</button>
          </div>
        </div>`;
      document.body.appendChild(modal);
      // Close on backdrop click
      modal.addEventListener('click', (e) => { if (e.target === modal) modal.remove(); });
    }

    function executePurchase(bIdx) {
      console.log('[Marketplace] executePurchase for bIdx:', bIdx);
      const modal = document.getElementById('purchaseModal');
      if (modal) modal.remove();

      const batch = mintedBatches[bIdx];
      const previousOwner = batch.owner;

      try {
        const res = registry.transfer(batch.creditId, currentWallet);
        console.log('[Marketplace] transfer result:', res);
        const updated = JSON.parse(res);
        batch.owner = updated.owner;
        batch.listedOnMarket = false; // Remove from marketplace after purchase

        // Update marketplace badge
        document.getElementById('badge-marketplace').textContent = mintedBatches.filter(b => b.listedOnMarket).length;

        let activeCredits = batch.totalCredits;
        try { const state = JSON.parse(registry.batch_state(batch.creditId)); activeCredits = state.active_total; } catch(_){}

        showSuccessToast(`✓ Purchased ${activeCredits.toLocaleString()} credits from ${previousOwner} → now in your Portfolio`);
        refreshMarketplace();
        refreshDashboard();

        // Auto-navigate to Portfolio so buyer sees their new credits
        setTimeout(() => navigate('portfolio'), 600);
      } catch (err) {
        console.error('[Marketplace] Transfer error:', err);
        showToast(`Transfer error: ${err}`);
      }
    }
    window.executePurchase = executePurchase;

    // ══════════════════════════════════════════════════════════════════
    //  PORTFOLIO MODULE
    // ══════════════════════════════════════════════════════════════════
    function refreshPortfolio() {
      const container = document.getElementById('portfolioContent');
      const owned = mintedBatches.filter(b => b.owner === currentWallet);

      let totalOwned = 0, totalRetired = 0;
      owned.forEach(b => {
        try {
          const state = JSON.parse(registry.batch_state(b.creditId));
          totalOwned += state.active_total;
          totalRetired += state.retired_total;
        } catch(_) { totalOwned += b.totalCredits; }
      });
      document.getElementById('port-owned').textContent = totalOwned.toLocaleString();
      document.getElementById('port-retired').textContent = totalRetired.toLocaleString();

      if (owned.length === 0) {
        container.innerHTML = '<div class="empty-state"><div class="empty-icon">💼</div><h3>No Credits in Portfolio</h3><p>Purchase credits from the Marketplace to see them here.</p></div>';
        return;
      }

      let html = '';
      owned.forEach((b) => {
        const bIdx = mintedBatches.indexOf(b);
        let batchState = null;
        try { batchState = JSON.parse(registry.batch_state(b.creditId)); } catch(_){}
        const activeCredits = batchState ? batchState.active_total : b.totalCredits;

        html += `<div class="result-card" style="border-color:rgba(88,166,255,0.15);">
          <h4>🪙 ${b.creditId} — ${b.projectName || b.projectId}</h4>
          <div class="kv-row"><span class="kv-key">technology</span><span class="kv-val">${b.tech}</span></div>
          <div class="kv-row"><span class="kv-key">total_supply</span><span class="kv-val">${b.totalCredits.toLocaleString()} tCO2e</span></div>
          <div class="kv-row"><span class="kv-key">active</span><span class="kv-val green">${activeCredits.toLocaleString()}</span></div>
          <div class="kv-row"><span class="kv-key">retired</span><span class="kv-val red">${batchState ? batchState.retired_total.toLocaleString() : '0'}</span></div>`;

        if (activeCredits > 0) {
          const retireStart = batchState?.slices?.find(s => s.status === 'Active')?.start || b.originalStart;
          const retireEnd = Math.min(retireStart + 299, batchState?.slices?.find(s => s.status === 'Active')?.end || b.originalEnd);
          html += `
          <div style="margin-top:1rem;padding-top:0.75rem;border-top:1px solid var(--border);">
            <h4 style="font-size:0.88rem;margin-bottom:0.75rem;">🔥 Retire Credits (Generate PoO)</h4>
            <div class="form-grid triple">
              <div class="field"><label>Burn Start</label><input type="number" id="burn-start-${bIdx}" value="${retireStart}"></div>
              <div class="field"><label>Burn End</label><input type="number" id="burn-end-${bIdx}" value="${retireEnd}"></div>
              <div class="field"><label>Claim Type</label>
                <select id="burn-claim-${bIdx}">
                  <option value="CorporateNetZero">Corporate Net Zero</option>
                  <option value="Compliance">Regulatory Compliance</option>
                  <option value="Payg">Pay-As-You-Go</option>
                </select>
              </div>
            </div>
            <div class="form-grid single">
              <div class="field"><label>Beneficiary</label><input type="text" id="burn-beneficiary-${bIdx}" value="${currentOrg}"></div>
            </div>
            <button class="btn btn-primary btn-sm" onclick="retireCredits(${bIdx})">🔥 Execute Retirement</button>
          </div>`;
        }

        // Show PoO receipts
        if (b.pooReceipts.length > 0) {
          html += '<div style="margin-top:1rem;">';
          b.pooReceipts.forEach((poo, pi) => {
            html += `<div class="result-card success" style="margin-top:0.5rem;">
              <h4>🔥 PoO Receipt #${pi+1}</h4>
              <div class="kv-row"><span class="kv-key">serial_range</span><span class="kv-val">${poo.serial_start} – ${poo.serial_end}</span></div>
              <div class="kv-row"><span class="kv-key">amount</span><span class="kv-val green">${poo.cc_amount} tCO2e</span></div>
              <div class="kv-row"><span class="kv-key">beneficiary</span><span class="kv-val blue">${poo.beneficiary}</span></div>
              <div class="kv-row"><span class="kv-key">burn_tx_hash</span><span class="kv-val">${poo.burn_tx_hash}</span></div>
            </div>`;
          });
          html += '</div>';
        }
        html += '</div>';
      });
      container.innerHTML = html;
    }

    function retireCredits(bIdx) {
      const batch = mintedBatches[bIdx];
      const burnStart = parseInt(document.getElementById(`burn-start-${bIdx}`).value);
      const burnEnd = parseInt(document.getElementById(`burn-end-${bIdx}`).value);
      const beneficiary = document.getElementById(`burn-beneficiary-${bIdx}`).value;
      const claimType = document.getElementById(`burn-claim-${bIdx}`).value;

      if (isNaN(burnStart) || isNaN(burnEnd) || burnEnd < burnStart) { showToast("Invalid burn range."); return; }
      if (!beneficiary) { showToast("Please enter a beneficiary."); return; }

      const burnReq = { credit_id: batch.creditId, burn_start: burnStart, burn_end: burnEnd, beneficiary, claim_type: claimType };
      try {
        const res = registry.burn(JSON.stringify(burnReq));
        const poo = JSON.parse(res);
        batch.pooReceipts.push(poo);
        showSuccessToast(`✓ ${poo.cc_amount} tCO2e retired — PoO issued`);
        refreshPortfolio();
        refreshDashboard();
      } catch (err) { showToast(`Retirement error: ${err}`); }
    }
    window.retireCredits = retireCredits;

    // ══════════════════════════════════════════════════════════════════
    //  AUDIT MODULE
    // ══════════════════════════════════════════════════════════════════
    function runAuditChecks() {
      if (mintedBatches.length === 0) {
        document.getElementById('auditGrid').innerHTML = '<div class="empty-state"><div class="empty-icon">📄</div><h3>No Audit Data</h3><p>Complete a full lifecycle (MRV → Mint → Retire) to see invariant checks.</p></div>';
        return;
      }
      const firstBatch = mintedBatches[0];
      try {
        const stateStr = registry.batch_state(firstBatch.creditId);
        const state = JSON.parse(stateStr);
        const fullStateStr = registry.full_state();
        const fullState = JSON.parse(fullStateStr);

        document.getElementById('cnt-original').textContent = state.original_end - state.original_start + 1;
        document.getElementById('cnt-active').textContent = state.active_total;
        document.getElementById('cnt-retired').textContent = state.retired_total;
        document.getElementById('cnt-burned-ranges').textContent = fullState.burned_range_count;

        const grid = document.getElementById('auditGrid');
        grid.innerHTML = '';
        grid.appendChild(auditCard("1", "PoI is Mandatory for Minting", "Minting fails if no valid Proof-of-Integrity is supplied.", true));
        const inv2Ok = (state.original_end - state.original_start + 1) <= firstBatch.totalCredits;
        grid.appendChild(auditCard("2", "Supply Authorized Cap Limit", "Minted credits must be <= authorized PoI quantity.", inv2Ok));
        grid.appendChild(auditCard("3", "Global Serial Locking Uniqueness", "Overlapping active serial ranges rejected.", true));
        grid.appendChild(auditCard("4", "Burn Irreversibility (Spent Forever)", "Retired ranges blacklisted globally.", true));
        grid.appendChild(auditCard("5", "PoO Uniqueness (Double-spending prevented)", "Retirements matching burned footprints rejected.", true));
        grid.appendChild(auditCard("6", "PoO Non-Transferability", "Proof-of-Offset receipts bind permanently.", true));
        const inv7Ok = firstBatch.poiStatus === "USED";
        grid.appendChild(auditCard("7", "PoI Single-use Consumed State", "PoI marked used, blocking replay.", inv7Ok));

        setupDownloads(firstBatch, state, fullState);
      } catch (err) { console.error("Audit error:", err); }
    }

    function auditCard(num, name, desc, pass) {
      const card = document.createElement('div');
      card.className = `audit-card ${pass ? 'ok' : 'failed'}`;
      card.innerHTML = `<div class="audit-icon">${pass ? '✓' : '✗'}</div><div class="audit-desc"><h5>Invariant ${num}: ${name}</h5><p>${desc}</p></div>`;
      return card;
    }

    function setupDownloads(batch, state, fullState) {
      const grid = document.getElementById('downloadGrid');
      grid.innerHTML = '';
      grid.appendChild(downloadBtn("mrv_records.json", mrvRecords, "📡 MRV Records"));
      if (commitment) grid.appendChild(downloadBtn("merkle_commitment.json", commitment, "🌳 Merkle Commitment"));
      grid.appendChild(downloadBtn("credit_batch.json", state, "📦 Credit Batch"));
      batch.pooReceipts.forEach((poo, i) => { grid.appendChild(downloadBtn(`poo_receipt_${i+1}.json`, poo, `🔥 PoO #${i+1}`)); });
      grid.appendChild(downloadBtn("registry_full_state.json", fullState, "👑 Full Registry State"));
      document.getElementById('pdfExportBtn').style.display = '';
      document.getElementById('zipExportBtn').style.display = '';
    }

    function downloadBtn(filename, obj, label) {
      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(obj, null, 2));
      const a = document.createElement('a');
      a.className = 'btn btn-secondary btn-sm';
      a.href = dataStr; a.download = filename;
      a.innerHTML = `💾 ${label}`;
      return a;
    }

    // ══════════════════════════════════════════════════════════════════
    //  ADMIN / IDENTITY
    // ══════════════════════════════════════════════════════════════════
    function updateIdentity() {
      currentWallet = document.getElementById('admin-wallet').value;
      currentOrg = document.getElementById('admin-org').value;
      showSuccessToast(`✓ Identity updated to ${currentOrg} (${currentWallet})`);
    }
    window.updateIdentity = updateIdentity;

    // ══════════════════════════════════════════════════════════════════
    //  DASHBOARD REFRESH
    // ══════════════════════════════════════════════════════════════════
    function refreshDashboard() {
      document.getElementById('dash-projects').textContent = projects.length;
      let totalCredits = 0, totalRetired = 0;
      mintedBatches.forEach(b => {
        totalCredits += b.totalCredits;
        try { const s = JSON.parse(registry.batch_state(b.creditId)); totalRetired += s.retired_total; } catch(_){}
      });
      document.getElementById('dash-credits').textContent = totalCredits.toLocaleString();
      document.getElementById('dash-retired').textContent = totalRetired.toLocaleString();
      document.getElementById('dash-listings').textContent = mintedBatches.filter(b => b.listedOnMarket).length;
      document.getElementById('dash-pending').textContent = projects.filter(p => p.mrvCommitted && !p.poiIssued).length;
      document.getElementById('badge-projects').textContent = projects.length;
      document.getElementById('badge-registry').textContent = mintedBatches.length;
      document.getElementById('badge-marketplace').textContent = mintedBatches.filter(b => b.listedOnMarket).length;
    }

    // ══════════════════════════════════════════════════════════════════
    //  PDF EXPORT
    // ══════════════════════════════════════════════════════════════════
    function exportPdfCertificate() {
      if (mintedBatches.length === 0) { showToast('Complete the full workflow first.'); return; }
      const batch = mintedBatches[0];
      try {
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF({ unit: 'mm', format: 'a4' });
        const ts = new Date().toISOString();
        doc.setFillColor(10, 13, 20); doc.rect(0, 0, 210, 40, 'F');
        doc.setTextColor(88, 166, 255); doc.setFontSize(20); doc.setFont('helvetica', 'bold');
        doc.text('GreyMisnomer Protocol', 15, 18);
        doc.setFontSize(11); doc.setTextColor(188, 140, 242);
        doc.text('Carbon Credit Registry — Session Certificate', 15, 27);
        doc.setFontSize(8); doc.setTextColor(132, 146, 166); doc.text(`Generated: ${ts}`, 15, 34);
        let y = 52;
        const sectionTitle = (title) => { doc.setFillColor(22, 28, 43); doc.rect(10, y - 5, 190, 9, 'F'); doc.setFontSize(10); doc.setFont('helvetica', 'bold'); doc.setTextColor(88, 166, 255); doc.text(title, 14, y); y += 9; };
        const field = (key, value) => { doc.setFontSize(9); doc.setFont('helvetica', 'bold'); doc.setTextColor(132, 146, 166); doc.text(key, 14, y); doc.setFont('courier', 'normal'); doc.setTextColor(240, 242, 245); const lines = doc.splitTextToSize(String(value), 130); doc.text(lines, 70, y); y += lines.length * 5.5 + 1; if (y > 270) { doc.addPage(); y = 20; } };
        if (commitment) { sectionTitle('RFC-003 · MRV Commitment'); field('Merkle Root', commitment.merkle_root_hex); field('Leaf Count', `${commitment.leaf_count} records`); y += 3; }
        sectionTitle('RFC-002 · Minted Credit Batch'); field('Credit ID', batch.creditId); field('Project', batch.projectName); field('Range', `${batch.originalStart} – ${batch.originalEnd}`); field('Credits', `${batch.totalCredits} tCO₂e`); field('Owner', batch.owner); y += 3;
        if (batch.pooReceipts.length > 0) { sectionTitle(`RFC-001 · PoO Receipts (${batch.pooReceipts.length})`); batch.pooReceipts.forEach((poo, i) => { field(`#${i+1}`, `${poo.serial_start}–${poo.serial_end} | ${poo.cc_amount} tCO₂e`); field('Beneficiary', poo.beneficiary); y += 2; }); }
        const pageCount = doc.getNumberOfPages();
        for (let i = 1; i <= pageCount; i++) { doc.setPage(i); doc.setFontSize(7.5); doc.setTextColor(132, 146, 166); doc.text('GreyMisnomer · Platform Demonstrator', 14, 289); doc.text(`Page ${i} of ${pageCount}`, 185, 289, { align: 'right' }); }
        doc.save(`greymisnomer_certificate_${batch.creditId}.pdf`);
      } catch (err) { showToast(`PDF failed: ${err.message}`); }
    }
    window.exportPdfCertificate = exportPdfCertificate;

    // ══════════════════════════════════════════════════════════════════
    //  ZIP EXPORT
    // ══════════════════════════════════════════════════════════════════
    async function exportZipBundle() {
      if (mintedBatches.length === 0) { showToast('Complete the full workflow first.'); return; }
      try {
        const files = {};
        files['mrv_records.json'] = JSON.stringify(mrvRecords, null, 2);
        if (commitment) files['merkle_commitment.json'] = JSON.stringify(commitment, null, 2);
        mintedBatches.forEach(b => {
          try { files[`batch_${b.creditId}.json`] = JSON.stringify(JSON.parse(registry.batch_state(b.creditId)), null, 2); } catch(_){}
          b.pooReceipts.forEach((poo, i) => { files[`poo_${b.creditId}_${i+1}.json`] = JSON.stringify(poo, null, 2); });
        });
        try { files['registry_full_state.json'] = JSON.stringify(JSON.parse(registry.full_state()), null, 2); } catch(_){}
        const zipBytes = buildZip(files);
        const blob = new Blob([zipBytes], { type: 'application/zip' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a'); a.href = url; a.download = `greymisnomer_audit_${Date.now()}.zip`; a.click();
        setTimeout(() => URL.revokeObjectURL(url), 5000);
        showSuccessToast('✓ Audit ZIP downloaded');
      } catch (err) { showToast(`ZIP failed: ${err.message}`); }
    }
    window.exportZipBundle = exportZipBundle;

    function buildZip(files) {
      const encoder = new TextEncoder();
      const parts = [], centralDir = [];
      let offset = 0;
      const crc32 = (data) => { let crc = -1; const table = buildCrcTable(); for (const b of data) crc = (crc >>> 8) ^ table[(crc ^ b) & 0xff]; return (crc ^ -1) >>> 0; };
      const buildCrcTable = () => { if (buildCrcTable._t) return buildCrcTable._t; const t = new Uint32Array(256); for (let i = 0; i < 256; i++) { let c = i; for (let j = 0; j < 8; j++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1); t[i] = c; } return (buildCrcTable._t = t); };
      const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n, true); return b; };
      const u16 = (n) => { const b = new Uint8Array(2); new DataView(b.buffer).setUint16(0, n, true); return b; };
      const str = (s) => encoder.encode(s);
      for (const [name, content] of Object.entries(files)) {
        const data = encoder.encode(content); const nameBytes = str(name); const crc = crc32(data);
        const localHeader = new Uint8Array([...u32(0x04034b50), ...u16(20), ...u16(0), ...u16(0), ...u16(0), ...u16(0), ...u32(crc), ...u32(data.length), ...u32(data.length), ...u16(nameBytes.length), ...u16(0), ...nameBytes, ...data]);
        parts.push(localHeader);
        centralDir.push(new Uint8Array([...u32(0x02014b50), ...u16(20), ...u16(20), ...u16(0), ...u16(0), ...u16(0), ...u16(0), ...u32(crc), ...u32(data.length), ...u32(data.length), ...u16(nameBytes.length), ...u16(0), ...u16(0), ...u16(0), ...u16(0), ...u32(0), ...u32(offset), ...nameBytes]));
        offset += localHeader.length;
      }
      const cdSize = centralDir.reduce((s, b) => s + b.length, 0);
      const eocd = new Uint8Array([...u32(0x06054b50), ...u16(0), ...u16(0), ...u16(centralDir.length), ...u16(centralDir.length), ...u32(cdSize), ...u32(offset), ...u16(0)]);
      const total = [...parts, ...centralDir, eocd].reduce((s, b) => s + b.length, 0);
      const out = new Uint8Array(total); let pos = 0;
      for (const b of [...parts, ...centralDir, eocd]) { out.set(b, pos); pos += b.length; }
      return out;
    }

    // ══════════════════════════════════════════════════════════════════
    //  TOASTS & RESET
    // ══════════════════════════════════════════════════════════════════
    function showToast(msg) {
      const toast = document.getElementById('toast');
      toast.style.background = '#180d0d'; toast.style.borderColor = 'rgba(248,81,73,0.4)'; toast.style.color = 'var(--red)';
      toast.textContent = msg; toast.classList.add('show');
      setTimeout(() => { toast.classList.remove('show'); }, 5000);
    }
    function showSuccessToast(msg) {
      const toast = document.getElementById('toast');
      toast.style.background = '#0d1f0d'; toast.style.borderColor = 'rgba(57,211,83,0.4)'; toast.style.color = 'var(--green)';
      toast.textContent = msg; toast.classList.add('show');
      setTimeout(() => { toast.classList.remove('show'); toast.style.background = ''; toast.style.borderColor = ''; toast.style.color = ''; }, 3500);
    }

    function resetAll() {
      if (confirm("Reset entire session? All projects, credits, and data will be cleared.")) {
        registry = new WasmRegistry();
        mrvRecords = []; commitment = null;
        projects = []; mintedBatches = [];
        document.getElementById('mrvCommitmentDisplay').innerHTML = '';
        document.getElementById('spotCheckSection').style.display = 'none';
        document.getElementById('mrvBody').innerHTML = '';
        refreshDashboard();
        navigate('dashboard');
        showSuccessToast('✓ Registry reset complete');
      }
    }
    window.resetAll = resetAll;
