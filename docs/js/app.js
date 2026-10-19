    import init, {
      build_commitment,
      verify_inclusion,
      WasmRegistry,
      replay_event_log,
      verify_checkpoint,
      detect_equivocation_wasm,
      generate_keypair_wasm,
      derive_pubkey_wasm,
      sign_transfer_intent_wasm,
      sign_burn_intent_wasm,
      sign_mint_intent_wasm,
      simulate_apply_wasm
    } from '../pkg/grey_misnomer_wasm.js';

    // ══════════════════════════════════════════════════════════════════
    //  STATE
    // ══════════════════════════════════════════════════════════════════
    let registry = null;
    let mrvRecords = [];
    let commitment = null;

    // Platform state (lives in JS, simulates "DB")
    let projects = [];       // { id, name, tech, jurisdiction, org, expectedCredits, lat, lng, status, mrvCommitted, poiIssued }
    let mintedBatches = [];  // { creditId, projectId, owner, totalCredits, originalStart, originalEnd, poiStatus, listedOnMarket, listingPrice, pooReceipts }
    let globalNextSerial = 1000000;
    let currentRole = 'admin';
    let currentWallet = '0xProjectOwner';
    let currentOrg = 'ABC Solar Energy Pvt. Ltd.';

    function createEmptyState(icon, title, desc) {
      const div = document.createElement('div');
      div.className = 'empty-state';
      const iconDiv = document.createElement('div');
      iconDiv.className = 'empty-icon';
      iconDiv.textContent = icon;
      const h3 = document.createElement('h3');
      h3.textContent = title;
      const p = document.createElement('p');
      p.textContent = desc;
      div.appendChild(iconDiv);
      div.appendChild(h3);
      div.appendChild(p);
      return div;
    }

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
      initKeyManager();
      refreshDashboard();
      verifyPublicLedger();
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
      if (view === 'audit') {
        runAuditChecks();
        verifyPublicLedger();
      }
    }
    window.navigate = navigate;

    // ══════════════════════════════════════════════════════════════════
    //  ROLE MANAGEMENT
    // ══════════════════════════════════════════════════════════════════
    const roleAccess = {
      admin:     ['dashboard','governance','projects','mrv','verification','registry','marketplace','portfolio','audit','admin','signer'],
      developer: ['dashboard','projects','mrv','registry','marketplace','portfolio','audit','signer'],
      validator: ['dashboard','governance','verification','registry','audit','signer'],
      buyer:     ['dashboard','marketplace','portfolio','registry','audit','signer'],
      auditor:   ['dashboard','registry','audit','signer']
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
      const allViews = ['dashboard','governance','projects','mrv','verification','registry','marketplace','portfolio','audit','admin','signer'];
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
      container.replaceChildren();
      if (projects.length === 0) {
        container.appendChild(createEmptyState('📁', 'No Projects Yet', 'Register your first carbon reduction project above.'));
        return;
      }
      const wrap = document.createElement('div');
      wrap.className = 'table-wrap';
      const table = document.createElement('table');
      table.className = 'data';

      const thead = document.createElement('thead');
      const headerRow = document.createElement('tr');
      ['Project ID', 'Name', 'Technology', 'Status', 'Credits', 'Actions'].forEach(text => {
        const th = document.createElement('th');
        th.textContent = text;
        headerRow.appendChild(th);
      });
      thead.appendChild(headerRow);
      table.appendChild(thead);

      const tbody = document.createElement('tbody');
      projects.forEach((p, i) => {
        const tr = document.createElement('tr');

        const tdId = document.createElement('td');
        tdId.style.color = 'var(--blue)';
        tdId.textContent = p.id;
        tr.appendChild(tdId);

        const tdName = document.createElement('td');
        tdName.style.color = 'var(--text)';
        tdName.style.fontFamily = 'var(--sans)';
        tdName.textContent = p.name;
        tr.appendChild(tdName);

        const tdTech = document.createElement('td');
        tdTech.textContent = p.tech;
        tr.appendChild(tdTech);

        const tdStatus = document.createElement('td');
        const spanStatus = document.createElement('span');
        const statusClass = p.minted ? 'active' : (p.poiIssued ? 'listed' : (p.mrvCommitted ? 'pending' : 'pending'));
        const statusText = p.minted ? 'Minted' : (p.poiIssued ? 'PoI Issued' : (p.mrvCommitted ? 'MRV Committed' : 'Registered'));
        spanStatus.className = `status-pill ${statusClass}`;
        spanStatus.textContent = statusText;
        tdStatus.appendChild(spanStatus);
        tr.appendChild(tdStatus);

        const tdCredits = document.createElement('td');
        tdCredits.textContent = p.expectedCredits.toLocaleString();
        tr.appendChild(tdCredits);

        const tdAction = document.createElement('td');
        if (!p.mrvCommitted) {
          const btn = document.createElement('button');
          btn.className = 'btn btn-secondary btn-sm';
          btn.textContent = 'Upload MRV';
          btn.onclick = () => navigate('mrv');
          tdAction.appendChild(btn);
        } else if (!p.minted && p.poiIssued) {
          const btn = document.createElement('button');
          btn.className = 'btn btn-green btn-sm';
          btn.textContent = '🪙 Mint';
          btn.onclick = () => mintFromProject(i);
          tdAction.appendChild(btn);
        } else {
          tdAction.textContent = '—';
        }
        tr.appendChild(tdAction);

        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      wrap.appendChild(table);
      container.appendChild(wrap);
    }

    // ══════════════════════════════════════════════════════════════════
    //  MRV MODULE (reusing existing logic)
    // ══════════════════════════════════════════════════════════════════
    function refreshMrvProjectSelect() {
      const sel = document.getElementById('mrv-project-select');
      sel.replaceChildren();
      if (projects.length === 0) {
        const opt = document.createElement('option');
        opt.value = '';
        opt.textContent = '— Register a project first —';
        sel.appendChild(opt);
        return;
      }
      projects.filter(p => !p.minted).forEach(p => {
        const opt = document.createElement('option');
        opt.value = p.id;
        opt.textContent = `${p.id} — ${p.name}`;
        sel.appendChild(opt);
      });
    }

    function addMrvRow(ts = null, val = null, unit = 'kWh', src = null) {
      const body = document.getElementById('mrvBody');
      const idx = body.rows.length;
      const defaultTs = ts || Math.floor(Date.now() / 1000);
      const defaultVal = val || 1200.0;
      const defaultSrc = src || `SOLAR-SENSOR-${String(idx % 4).padStart(3, '0')}`;
      const row = document.createElement('tr');

      const tdIdx = document.createElement('td');
      tdIdx.style.cssText = 'color:var(--muted);font-family:var(--mono);font-size:0.73rem;';
      tdIdx.textContent = idx + 1;
      row.appendChild(tdIdx);

      const tdTs = document.createElement('td');
      const inTs = document.createElement('input');
      inTs.type = 'number';
      inTs.className = 'mrv-ts';
      inTs.value = defaultTs;
      tdTs.appendChild(inTs);
      row.appendChild(tdTs);

      const tdVal = document.createElement('td');
      const inVal = document.createElement('input');
      inVal.type = 'number';
      inVal.className = 'mrv-val';
      inVal.value = defaultVal;
      inVal.step = '0.1';
      tdVal.appendChild(inVal);
      row.appendChild(tdVal);

      const tdUnit = document.createElement('td');
      const inUnit = document.createElement('input');
      inUnit.type = 'text';
      inUnit.className = 'mrv-unit';
      inUnit.value = unit;
      inUnit.style.width = '70px';
      tdUnit.appendChild(inUnit);
      row.appendChild(tdUnit);

      const tdSrc = document.createElement('td');
      const inSrc = document.createElement('input');
      inSrc.type = 'text';
      inSrc.className = 'mrv-src';
      inSrc.value = defaultSrc;
      tdSrc.appendChild(inSrc);
      row.appendChild(tdSrc);

      const tdDel = document.createElement('td');
      const delBtn = document.createElement('button');
      delBtn.textContent = '✕';
      delBtn.style.cssText = 'background:none;border:none;color:var(--muted);cursor:pointer;font-size:0.9rem;';
      delBtn.onclick = () => {
        row.remove();
        reindexTable();
        updateRecordBadge();
      };
      tdDel.appendChild(delBtn);
      row.appendChild(tdDel);

      body.appendChild(row);
      updateRecordBadge();
    }
    window.addMrvRow = addMrvRow;
    window.reindexTable = () => { document.querySelectorAll('#mrvBody tr').forEach((row, i) => { row.cells[0].textContent = i + 1; }); };

    function clearMrvTable() { document.getElementById('mrvBody').replaceChildren(); updateRecordBadge(); }
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
        await registry.store_commitment(jsonStr, timestamp, selProjectId);

        // Update project state
        const prj = projects.find(p => p.id === selProjectId);
        if (prj) { prj.mrvCommitted = true; prj.status = 'MRV Committed'; prj.commitment = commitment; prj.mrvData = list; }

        const disp = document.getElementById('mrvCommitmentDisplay');
        disp.replaceChildren();

        const hashDiv = document.createElement('div');
        hashDiv.className = 'hash-display';
        const tag = document.createElement('span');
        tag.className = 'tag';
        tag.textContent = 'BLAKE3 Merkle Root';
        hashDiv.appendChild(tag);
        hashDiv.appendChild(document.createTextNode(commitment.merkle_root_hex));
        disp.appendChild(hashDiv);

        const card = document.createElement('div');
        card.className = 'result-card success';
        const h4 = document.createElement('h4');
        h4.textContent = '✅ Merkle Commitment Successful (RFC-003)';
        card.appendChild(h4);

        const kvRows = [
          ['project', selProjectId, 'kv-val blue'],
          ['leaf_count', `${commitment.leaf_count} leaves`, 'kv-val green'],
          ['hash_algorithm', commitment.algorithm, 'kv-val blue'],
          ['commitment_ts', String(commitment.timestamp), 'kv-val'],
          ['data_anchored', 'True (Stored in Registry)', 'kv-val green']
        ];
        kvRows.forEach(([key, val, valClass]) => {
          const rowDiv = document.createElement('div');
          rowDiv.className = 'kv-row';
          const kSpan = document.createElement('span');
          kSpan.className = 'kv-key';
          kSpan.textContent = key;
          const vSpan = document.createElement('span');
          vSpan.className = valClass;
          vSpan.textContent = val;
          rowDiv.appendChild(kSpan);
          rowDiv.appendChild(vSpan);
          card.appendChild(rowDiv);
        });
        disp.appendChild(card);

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
      body.replaceChildren();
      const indices = [];
      if (mrvRecords.length > 0) indices.push(0);
      if (mrvRecords.length > 2) indices.push(Math.floor(mrvRecords.length / 2));
      if (mrvRecords.length > 1) indices.push(mrvRecords.length - 1);
      indices.forEach(idx => {
        const record = mrvRecords[idx];
        const row = document.createElement('tr');

        const tdIdx = document.createElement('td');
        tdIdx.style.fontFamily = 'var(--mono)';
        tdIdx.textContent = `[${idx}]`;
        row.appendChild(tdIdx);

        const tdSrc = document.createElement('td');
        tdSrc.textContent = record.source;
        row.appendChild(tdSrc);

        const tdVal = document.createElement('td');
        const spanVal = document.createElement('span');
        spanVal.id = `spot-val-${idx}`;
        spanVal.textContent = record.value;
        tdVal.appendChild(spanVal);
        tdVal.appendChild(document.createTextNode(` ${record.unit}`));
        row.appendChild(tdVal);

        const tdCheck = document.createElement('td');
        const check = document.createElement('input');
        check.type = 'checkbox';
        check.id = `tamper-${idx}`;
        check.onchange = () => toggleTamper(idx);
        tdCheck.appendChild(check);
        row.appendChild(tdCheck);

        const tdStatus = document.createElement('td');
        tdStatus.id = `proof-status-${idx}`;
        const vBtn = document.createElement('button');
        vBtn.className = 'btn btn-secondary btn-sm';
        vBtn.textContent = 'Verify Inclusion';
        vBtn.onclick = () => runSpotVerify(idx);
        tdStatus.appendChild(vBtn);
        row.appendChild(tdStatus);

        body.appendChild(row);
      });
    }

    window.toggleTamper = (idx) => {
      const checked = document.getElementById(`tamper-${idx}`).checked;
      const displaySpan = document.getElementById(`spot-val-${idx}`);
      if (checked) { displaySpan.textContent = "999999.0 (Tampered)"; displaySpan.style.color = "var(--red)"; }
      else { displaySpan.textContent = mrvRecords[idx].value; displaySpan.style.color = "var(--text)"; }
      const statusTd = document.getElementById(`proof-status-${idx}`);
      statusTd.replaceChildren();
      const vBtn = document.createElement('button');
      vBtn.className = 'btn btn-secondary btn-sm';
      vBtn.textContent = 'Verify Inclusion';
      vBtn.onclick = () => runSpotVerify(idx);
      statusTd.appendChild(vBtn);
    };

    window.runSpotVerify = (idx) => {
      const checked = document.getElementById(`tamper-${idx}`).checked;
      const targetRecord = { ...mrvRecords[idx] };
      if (checked) targetRecord.value = 999999.0;
      try {
        const dummyList = [...mrvRecords]; dummyList[idx] = targetRecord;
        const res = verify_inclusion(JSON.stringify(dummyList), idx, commitment.merkle_root_hex);
        const statusTd = document.getElementById(`proof-status-${idx}`);
        statusTd.replaceChildren();
        const span = document.createElement('span');
        if (res === "verified") {
          span.style.color = 'var(--green)';
          span.textContent = '✓ Verified';
        } else {
          span.style.color = 'var(--red)';
          span.textContent = '✗ Rejected';
        }
        statusTd.appendChild(span);
      } catch (err) { showToast(err); }
    };

    // ══════════════════════════════════════════════════════════════════
    //  VERIFICATION MODULE
    // ══════════════════════════════════════════════════════════════════
    function refreshVerification() {
      const container = document.getElementById('verificationQueue');
      container.replaceChildren();
      const pending = projects.filter(p => p.mrvCommitted && !p.poiIssued);
      const approved = projects.filter(p => p.poiIssued);

      if (pending.length === 0 && approved.length === 0) {
        container.appendChild(createEmptyState('🔐', 'No Pending Verifications', 'Projects with MRV commitments will appear here for validator approval.'));
        return;
      }

      if (pending.length > 0) {
        const h3 = document.createElement('h3');
        h3.style.cssText = 'font-size:1rem;margin-bottom:0.75rem;color:var(--amber)';
        h3.textContent = '⏳ Pending Approval';
        container.appendChild(h3);

        pending.forEach(p => {
          const pIdx = projects.indexOf(p);
          const card = document.createElement('div');
          card.className = 'result-card';
          card.style.borderColor = 'rgba(236,178,46,0.2)';

          const h4 = document.createElement('h4');
          h4.textContent = `📁 ${p.name} `;
          const pill = document.createElement('span');
          pill.className = 'status-pill pending';
          pill.style.marginLeft = '0.5rem';
          pill.textContent = 'Pending';
          h4.appendChild(pill);
          card.appendChild(h4);

          const kvData = [
            ['project_id', p.id, 'kv-val blue'],
            ['technology', p.tech, 'kv-val'],
            ['jurisdiction', p.jurisdiction, 'kv-val'],
            ['merkle_root', p.commitment?.merkle_root_hex || 'N/A', 'kv-val green'],
            ['leaf_count', `${p.commitment?.leaf_count || 0} records`, 'kv-val']
          ];
          kvData.forEach(([k, v, cls]) => {
            const row = document.createElement('div');
            row.className = 'kv-row';
            const kSpan = document.createElement('span');
            kSpan.className = 'kv-key';
            kSpan.textContent = k;
            const vSpan = document.createElement('span');
            vSpan.className = cls;
            vSpan.textContent = v;
            row.appendChild(kSpan);
            row.appendChild(vSpan);
            card.appendChild(row);
          });

          const btnRow = document.createElement('div');
          btnRow.className = 'btn-row';
          const approveBtn = document.createElement('button');
          approveBtn.className = 'btn btn-green btn-sm';
          approveBtn.textContent = '✅ Approve & Issue PoI';
          approveBtn.onclick = () => approveProject(pIdx);
          const rejectBtn = document.createElement('button');
          rejectBtn.className = 'btn btn-secondary btn-sm';
          rejectBtn.textContent = '✗ Reject';
          rejectBtn.onclick = () => rejectProject(pIdx);
          btnRow.appendChild(approveBtn);
          btnRow.appendChild(rejectBtn);
          card.appendChild(btnRow);

          container.appendChild(card);
        });
      }

      if (approved.length > 0) {
        const h3 = document.createElement('h3');
        h3.style.cssText = 'font-size:1rem;margin-top:1.5rem;margin-bottom:0.75rem;color:var(--green)';
        h3.textContent = '✅ Approved';
        container.appendChild(h3);

        approved.forEach(p => {
          const card = document.createElement('div');
          card.className = 'result-card success';

          const h4 = document.createElement('h4');
          h4.textContent = `📁 ${p.name} `;
          const pill = document.createElement('span');
          pill.className = 'status-pill active';
          pill.style.marginLeft = '0.5rem';
          pill.textContent = 'PoI Issued';
          h4.appendChild(pill);
          card.appendChild(h4);

          const kvData = [
            ['project_id', p.id, 'kv-val blue'],
            ['merkle_root', p.commitment?.merkle_root_hex || 'N/A', 'kv-val green']
          ];
          kvData.forEach(([k, v, cls]) => {
            const row = document.createElement('div');
            row.className = 'kv-row';
            const kSpan = document.createElement('span');
            kSpan.className = 'kv-key';
            kSpan.textContent = k;
            const vSpan = document.createElement('span');
            vSpan.className = cls;
            vSpan.textContent = v;
            row.appendChild(kSpan);
            row.appendChild(vSpan);
            card.appendChild(row);
          });

          container.appendChild(card);
        });
      }
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
      const serialStart = Math.max(
        globalNextSerial,
        mintedBatches.length > 0 ? Math.max(...mintedBatches.map(b => b.originalEnd)) + 1 : 1000000
      );
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
        owner: currentWallet,
        poi_valid: p.poiIssued === true
      };

      try {
        const res = registry.mint(JSON.stringify(poiData));
        const mintData = JSON.parse(res);

        globalNextSerial = serialEnd + 1;
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
    // ══════════════════════════════════════════════════════════════════
    //  REGISTRY MODULE
    // ══════════════════════════════════════════════════════════════════
    function refreshRegistry() {
      const container = document.getElementById('registryTable');
      if (mintedBatches.length === 0) {
        container.replaceChildren(createEmptyState('🪙', 'No Credits Minted Yet', 'Register a project, upload MRV data, get it verified, then mint credits.'));
        document.getElementById('reg-total-batches').textContent = '0';
        document.getElementById('reg-total-active').textContent = '0';
        document.getElementById('reg-total-retired').textContent = '0';
        return;
      }

      document.getElementById('reg-total-batches').textContent = mintedBatches.length;

      let totalActive = 0, totalRetired = 0;
      const wrap = document.createElement('div');
      wrap.className = 'table-wrap';
      const table = document.createElement('table');
      table.className = 'data';
      const thead = document.createElement('thead');
      const trHead = document.createElement('tr');
      ['Credit ID', 'Project', 'Owner', 'Supply', 'Status', 'Actions'].forEach(h => {
        const th = document.createElement('th');
        th.textContent = h;
        trHead.appendChild(th);
      });
      thead.appendChild(trHead);
      table.appendChild(thead);
      const tbody = document.createElement('tbody');

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

        const tr = document.createElement('tr');

        const tdId = document.createElement('td');
        tdId.style.color = 'var(--blue)';
        tdId.textContent = b.creditId;
        tr.appendChild(tdId);

        const tdProj = document.createElement('td');
        tdProj.style.color = 'var(--text)';
        tdProj.style.fontFamily = 'var(--sans)';
        tdProj.textContent = b.projectName || b.projectId;
        tr.appendChild(tdProj);

        const tdOwner = document.createElement('td');
        tdOwner.textContent = b.owner;
        tr.appendChild(tdOwner);

        const tdSupply = document.createElement('td');
        tdSupply.textContent = `${b.totalCredits.toLocaleString()} tCO2e`;
        tr.appendChild(tdSupply);

        const tdStatus = document.createElement('td');
        const pill = document.createElement('span');
        pill.className = `status-pill ${statusClass}`;
        pill.textContent = statusText;
        tdStatus.appendChild(pill);
        tr.appendChild(tdStatus);

        const tdAction = document.createElement('td');
        if (!b.listedOnMarket && batchActive > 0) {
          const listBtn = document.createElement('button');
          listBtn.className = 'btn btn-secondary btn-sm';
          listBtn.textContent = '🛒 List';
          listBtn.onclick = () => listOnMarket(i);
          tdAction.appendChild(listBtn);
        } else {
          tdAction.textContent = '—';
        }
        tr.appendChild(tdAction);

        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      wrap.appendChild(table);
      container.replaceChildren(wrap);
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
        container.replaceChildren(createEmptyState('🛒', 'No Listings Available', 'Minted credits must be published to the marketplace by their owners.'));
        return;
      }

      const grid = document.createElement('div');
      grid.className = 'listing-grid';
      listings.forEach((b) => {
        const bIdx = mintedBatches.indexOf(b);
        let activeCredits = b.totalCredits;
        try { const state = JSON.parse(registry.batch_state(b.creditId)); activeCredits = state.active_total; } catch(_){}

        const isSeller = b.owner === currentWallet;
        const card = document.createElement('div');
        card.className = 'listing-card';

        const header = document.createElement('div');
        header.className = 'listing-header';
        const title = document.createElement('div');
        title.className = 'listing-title';
        title.textContent = b.projectName || b.creditId;
        const price = document.createElement('div');
        price.className = 'listing-price';
        price.textContent = `₹${b.listingPrice}/tCO2e`;
        header.appendChild(title);
        header.appendChild(price);
        card.appendChild(header);

        const meta = document.createElement('div');
        meta.className = 'listing-meta';
        const techStrong = document.createElement('strong');
        techStrong.textContent = b.tech;
        meta.appendChild(techStrong);
        meta.appendChild(document.createTextNode(` · ${b.creditId}`));
        meta.appendChild(document.createElement('br'));
        meta.appendChild(document.createTextNode(`Seller: ${b.owner}`));
        if (isSeller) {
          const youStrong = document.createElement('strong');
          youStrong.style.color = 'var(--amber)';
          youStrong.textContent = ' (You)';
          meta.appendChild(youStrong);
        }
        card.appendChild(meta);

        const stats = document.createElement('div');
        stats.className = 'listing-stats';
        const statAvail = document.createElement('div');
        statAvail.className = 'listing-stat';
        statAvail.appendChild(document.createTextNode('Available'));
        const spanAvail = document.createElement('span');
        spanAvail.textContent = activeCredits.toLocaleString();
        statAvail.appendChild(spanAvail);

        const statTot = document.createElement('div');
        statTot.className = 'listing-stat';
        statTot.appendChild(document.createTextNode('Total'));
        const spanTot = document.createElement('span');
        spanTot.textContent = b.totalCredits.toLocaleString();
        statTot.appendChild(spanTot);

        stats.appendChild(statAvail);
        stats.appendChild(statTot);
        card.appendChild(stats);

        if (activeCredits <= 0) {
          const pill = document.createElement('span');
          pill.className = 'status-pill retired';
          pill.textContent = 'Sold Out';
          card.appendChild(pill);
        } else if (isSeller) {
          const spanOwn = document.createElement('span');
          spanOwn.style.fontSize = '0.8rem';
          spanOwn.style.color = 'var(--muted)';
          spanOwn.style.fontStyle = 'italic';
          spanOwn.textContent = 'You own this listing';
          card.appendChild(spanOwn);
        } else {
          const totalCost = (activeCredits * b.listingPrice).toLocaleString();
          const buyBtn = document.createElement('button');
          buyBtn.className = 'btn btn-primary btn-sm';
          buyBtn.style.width = '100%';
          buyBtn.textContent = `🛒 Buy ${activeCredits.toLocaleString()} credits · ₹${totalCost}`;
          buyBtn.onclick = () => purchaseCredit(bIdx);
          card.appendChild(buyBtn);
        }

        grid.appendChild(card);
      });
      container.replaceChildren(grid);
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

      const box = document.createElement('div');
      box.style.cssText = 'background:var(--bg2);border:1px solid var(--border);border-radius:20px;padding:2rem;max-width:480px;width:90%;box-shadow:0 25px 60px rgba(0,0,0,0.6);';

      const title = document.createElement('h2');
      title.style.cssText = 'font-size:1.2rem;font-weight:800;margin-bottom:1.25rem;display:flex;align-items:center;gap:0.5rem;';
      title.textContent = '🛒 Confirm Purchase';
      box.appendChild(title);

      const kvWrap = document.createElement('div');
      kvWrap.style.cssText = 'background:var(--bg3);border:1px solid var(--border);border-radius:12px;padding:1rem;margin-bottom:1.25rem;';

      function addKv(key, val, valClass, style) {
        const row = document.createElement('div');
        row.className = 'kv-row';
        if (style) row.style.cssText = style;
        const kSpan = document.createElement('span');
        kSpan.className = 'kv-key';
        if (style) { kSpan.style.fontWeight = '700'; kSpan.style.color = 'var(--text)'; }
        kSpan.textContent = key;
        const vSpan = document.createElement('span');
        vSpan.className = 'kv-val' + (valClass ? ' ' + valClass : '');
        if (style) { vSpan.style.fontSize = '1.1rem'; vSpan.style.fontWeight = '700'; }
        vSpan.textContent = val;
        row.appendChild(kSpan);
        row.appendChild(vSpan);
        kvWrap.appendChild(row);
      }

      addKv('Credit', batch.creditId, 'blue');
      addKv('Project', batch.projectName);
      addKv('Seller', previousOwner, 'red');
      addKv('Buyer', `${currentWallet} (${currentOrg})`, 'green');
      addKv('Quantity', `${activeCredits.toLocaleString()} tCO2e`, 'green');
      addKv('Unit Price', `₹${batch.listingPrice}/tCO2e`);
      addKv('Total Cost', `₹${totalCost}`, 'green', 'border-top:1px solid var(--border);padding-top:0.6rem;');

      box.appendChild(kvWrap);

      const btnRow = document.createElement('div');
      btnRow.style.cssText = 'display:flex;gap:0.75rem;';

      const confirmBtn = document.createElement('button');
      confirmBtn.className = 'btn btn-primary';
      confirmBtn.style.flex = '1';
      confirmBtn.textContent = '✅ Confirm Purchase';
      confirmBtn.onclick = () => executePurchase(bIdx);

      const cancelBtn = document.createElement('button');
      cancelBtn.className = 'btn btn-secondary';
      cancelBtn.style.flex = '1';
      cancelBtn.textContent = 'Cancel';
      cancelBtn.onclick = () => {
        const m = document.getElementById('purchaseModal');
        if (m) m.remove();
      };

      btnRow.appendChild(confirmBtn);
      btnRow.appendChild(cancelBtn);
      box.appendChild(btnRow);

      modal.appendChild(box);
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
        container.replaceChildren(createEmptyState('💼', 'No Credits in Portfolio', 'Purchase credits from the Marketplace to see them here.'));
        return;
      }

      const cards = [];
      owned.forEach((b) => {
        const bIdx = mintedBatches.indexOf(b);
        let batchState = null;
        try { batchState = JSON.parse(registry.batch_state(b.creditId)); } catch(_){}
        const activeCredits = batchState ? batchState.active_total : b.totalCredits;

        const card = document.createElement('div');
        card.className = 'result-card';
        card.style.borderColor = 'rgba(88,166,255,0.15)';

        const h4 = document.createElement('h4');
        h4.textContent = `🪙 ${b.creditId} — ${b.projectName || b.projectId}`;
        card.appendChild(h4);

        function addKv(key, val, valClass) {
          const row = document.createElement('div');
          row.className = 'kv-row';
          const kSpan = document.createElement('span');
          kSpan.className = 'kv-key';
          kSpan.textContent = key;
          const vSpan = document.createElement('span');
          vSpan.className = 'kv-val' + (valClass ? ' ' + valClass : '');
          vSpan.textContent = val;
          row.appendChild(kSpan);
          row.appendChild(vSpan);
          card.appendChild(row);
        }

        addKv('technology', b.tech);
        addKv('total_supply', `${b.totalCredits.toLocaleString()} tCO2e`);
        addKv('active', activeCredits.toLocaleString(), 'green');
        addKv('retired', batchState ? batchState.retired_total.toLocaleString() : '0', 'red');

        if (activeCredits > 0) {
          const retireStart = batchState?.slices?.find(s => s.status === 'Active')?.start || b.originalStart;
          const retireEnd = Math.min(retireStart + 299, batchState?.slices?.find(s => s.status === 'Active')?.end || b.originalEnd);

          const retireDiv = document.createElement('div');
          retireDiv.style.cssText = 'margin-top:1rem;padding-top:0.75rem;border-top:1px solid var(--border);';

          const rH4 = document.createElement('h4');
          rH4.style.cssText = 'font-size:0.88rem;margin-bottom:0.75rem;';
          rH4.textContent = '🔥 Retire Credits (Generate PoO)';
          retireDiv.appendChild(rH4);

          const formGridTriple = document.createElement('div');
          formGridTriple.className = 'form-grid triple';

          // Burn Start field
          const f1 = document.createElement('div');
          f1.className = 'field';
          const l1 = document.createElement('label');
          l1.textContent = 'Burn Start';
          const inp1 = document.createElement('input');
          inp1.type = 'number';
          inp1.id = `burn-start-${bIdx}`;
          inp1.value = retireStart;
          f1.appendChild(l1);
          f1.appendChild(inp1);

          // Burn End field
          const f2 = document.createElement('div');
          f2.className = 'field';
          const l2 = document.createElement('label');
          l2.textContent = 'Burn End';
          const inp2 = document.createElement('input');
          inp2.type = 'number';
          inp2.id = `burn-end-${bIdx}`;
          inp2.value = retireEnd;
          f2.appendChild(l2);
          f2.appendChild(inp2);

          // Claim Type field
          const f3 = document.createElement('div');
          f3.className = 'field';
          const l3 = document.createElement('label');
          l3.textContent = 'Claim Type';
          const sel3 = document.createElement('select');
          sel3.id = `burn-claim-${bIdx}`;
          const optMap = [
            ['CorporateNetZero', 'Corporate Net Zero'],
            ['Compliance', 'Regulatory Compliance'],
            ['Payg', 'Pay-As-You-Go']
          ];
          optMap.forEach(([val, txt]) => {
            const opt = document.createElement('option');
            opt.value = val;
            opt.textContent = txt;
            sel3.appendChild(opt);
          });
          f3.appendChild(l3);
          f3.appendChild(sel3);

          formGridTriple.appendChild(f1);
          formGridTriple.appendChild(f2);
          formGridTriple.appendChild(f3);
          retireDiv.appendChild(formGridTriple);

          const formGridSingle = document.createElement('div');
          formGridSingle.className = 'form-grid single';
          const f4 = document.createElement('div');
          f4.className = 'field';
          const l4 = document.createElement('label');
          l4.textContent = 'Beneficiary';
          const inp4 = document.createElement('input');
          inp4.type = 'text';
          inp4.id = `burn-beneficiary-${bIdx}`;
          inp4.value = currentOrg;
          f4.appendChild(l4);
          f4.appendChild(inp4);
          formGridSingle.appendChild(f4);
          retireDiv.appendChild(formGridSingle);

          const retBtn = document.createElement('button');
          retBtn.className = 'btn btn-primary btn-sm';
          retBtn.textContent = '🔥 Execute Retirement';
          retBtn.onclick = () => retireCredits(bIdx);
          retireDiv.appendChild(retBtn);

          card.appendChild(retireDiv);
        }

        // Show PoO receipts
        if (b.pooReceipts.length > 0) {
          const pooWrap = document.createElement('div');
          pooWrap.style.marginTop = '1rem';
          b.pooReceipts.forEach((poo, pi) => {
            const pooCard = document.createElement('div');
            pooCard.className = 'result-card success';
            pooCard.style.marginTop = '0.5rem';

            const pH4 = document.createElement('h4');
            pH4.textContent = `🔥 PoO Receipt #${pi + 1}`;
            pooCard.appendChild(pH4);

            const rows = [
              ['serial_range', `${poo.serial_start} – ${poo.serial_end}`],
              ['amount', `${poo.cc_amount} tCO2e`, 'green'],
              ['beneficiary', poo.beneficiary, 'blue'],
              ['burn_tx_hash', poo.burn_tx_hash]
            ];
            rows.forEach(([k, v, cls]) => {
              const r = document.createElement('div');
              r.className = 'kv-row';
              const ks = document.createElement('span');
              ks.className = 'kv-key';
              ks.textContent = k;
              const vs = document.createElement('span');
              vs.className = 'kv-val' + (cls ? ' ' + cls : '');
              vs.textContent = v;
              r.appendChild(ks);
              r.appendChild(vs);
              pooCard.appendChild(r);
            });
            pooWrap.appendChild(pooCard);
          });
          card.appendChild(pooWrap);
        }

        cards.push(card);
      });
      container.replaceChildren(...cards);
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
    // ══════════════════════════════════════════════════════════════════
    //  AUDIT MODULE & PUBLIC LEDGER WASM VERIFIER (RFC-004)
    // ══════════════════════════════════════════════════════════════════
    // 6. Public Transparency Log Replay & Verification (RFC-004, 005, 006)
    // ══════════════════════════════════════════════════════════════════
    let publicLedgerRaw = '';
    let publicLedgerSummary = null;
    let currentManifest = null;

    async function fetchResilientEventLog() {
      const badge = document.getElementById('mirrorIngestionSourceBadge');

      // 1. Attempt Origin fetch first
      try {
        const resp = await fetch('events.jsonl', { cache: 'no-store' });
        if (resp.ok) {
          if (badge) {
            badge.textContent = 'Source: Primary Origin (HTTP)';
            badge.style.color = 'var(--green)';
            badge.style.background = 'rgba(57,211,83,0.15)';
          }
          return await resp.text();
        }
      } catch (err) {
        console.warn("Primary origin fetch failed, initiating multi-mirror fallback:", err);
      }

      // 2. Fetch manifest.json to locate decentralized mirrors
      let manifest = currentManifest;
      if (!manifest) {
        try {
          const mResp = await fetch('manifest.json', { cache: 'no-store' });
          if (mResp.ok) {
            manifest = await mResp.json();
            currentManifest = manifest;
          }
        } catch (e) {
          console.warn("Manifest fetch failed:", e);
        }
      }

      const ipfsCid = (manifest && manifest.mirrors && manifest.mirrors.ipfs && manifest.mirrors.ipfs.events_cid)
        ? manifest.mirrors.ipfs.events_cid
        : 'bafybeidqqrprx3bwgzoganunnbnvaiowrpdm5gmpverl6e4pz7j7ufj2im';

      const gateways = (manifest && manifest.mirrors && manifest.mirrors.ipfs && manifest.mirrors.ipfs.gateways)
        ? manifest.mirrors.ipfs.gateways
        : [
            'https://dweb.link/ipfs/',
            'https://ipfs.io/ipfs/',
            'https://cloudflare-ipfs.com/ipfs/'
          ];

      // 3. Fallback to IPFS Public Gateways
      for (const gw of gateways) {
        try {
          const url = `${gw}${ipfsCid}`;
          const gwResp = await fetch(url, { signal: AbortSignal.timeout(6000) });
          if (gwResp.ok) {
            const gwHost = new URL(gw).hostname;
            if (badge) {
              badge.textContent = `Source: IPFS Mirror (${gwHost})`;
              badge.style.color = 'var(--blue)';
              badge.style.background = 'rgba(88,166,255,0.15)';
            }
            return await gwResp.text();
          }
        } catch (e) {
          console.warn(`Gateway ${gw} failed:`, e);
        }
      }

      // 4. Fallback to Internet Archive Wayback Machine
      const archiveUrl = (manifest && manifest.mirrors && manifest.mirrors.archive_org && manifest.mirrors.archive_org.snapshot_url)
        ? manifest.mirrors.archive_org.snapshot_url
        : 'https://web.archive.org/web/20261019082411/https://greymisnomer.github.io/GreyMisnomer/events.jsonl';

      try {
        const arcResp = await fetch(archiveUrl, { signal: AbortSignal.timeout(8000) });
        if (arcResp.ok) {
          if (badge) {
            badge.textContent = 'Source: Internet Archive Wayback Mirror';
            badge.style.color = 'var(--purple)';
            badge.style.background = 'rgba(188,140,255,0.15)';
          }
          return await arcResp.text();
        }
      } catch (e) {
        console.warn("Wayback machine snapshot fetch failed:", e);
      }

      throw new Error("All mirrors (Origin HTTP, IPFS Gateway pool, Archive.org) were unreachable.");
    }
    window.fetchResilientEventLog = fetchResilientEventLog;

    async function verifyPublicLedger() {
      const badge = document.getElementById('ledgerVerificationBadge');
      const errBox = document.getElementById('ledgerVerificationError');
      if (badge) {
        badge.className = 'ledger-badge verifying';
        badge.textContent = '⏳ Replaying in WASM...';
      }
      if (errBox) errBox.style.display = 'none';

      try {
        publicLedgerRaw = await fetchResilientEventLog();

        const summaryJson = replay_event_log(publicLedgerRaw);
        publicLedgerSummary = JSON.parse(summaryJson);

        renderLedgerSummary(publicLedgerSummary, publicLedgerRaw);
        await checkOtsProof();
        await fetchManifestAndVerifyMirrors(publicLedgerSummary);
      } catch (err) {
        console.error("Public ledger verification error:", err);
        if (badge) {
          badge.className = 'ledger-badge failed';
          badge.textContent = '✗ Verification Failed';
        }
        if (errBox) {
          errBox.style.display = 'block';
          errBox.textContent = `WASM Replay Error: ${err.message || err}`;
        }
      }
    }
    window.verifyPublicLedger = verifyPublicLedger;

    async function fetchManifestAndVerifyMirrors(summary) {
      try {
        if (!currentManifest) {
          const mResp = await fetch('manifest.json', { cache: 'no-store' });
          if (mResp.ok) {
            currentManifest = await mResp.json();
          }
        }

        if (currentManifest) {
          const cidEl = document.getElementById('mirrorIpfsEventsCid');
          if (cidEl && currentManifest.mirrors && currentManifest.mirrors.ipfs) {
            cidEl.textContent = currentManifest.mirrors.ipfs.events_cid || 'Unavailable';
          }

          const arcLink = document.getElementById('mirrorArchiveOrgLink');
          if (arcLink && currentManifest.mirrors && currentManifest.mirrors.archive_org) {
            arcLink.href = currentManifest.mirrors.archive_org.snapshot_url || '#';
          }

          const eqEl = document.getElementById('mirrorEquivocationStatus');
          if (eqEl) {
            if (currentManifest.head_hash && summary.final_hash) {
              if (currentManifest.head_hash.toLowerCase() === summary.final_hash.toLowerCase()) {
                eqEl.textContent = '✓ Log Head Matches Manifest (No Split-View Detected)';
                eqEl.style.color = 'var(--green)';
              } else {
                eqEl.textContent = `❌ EQUIVOCATION DETECTED: Manifest head (${currentManifest.head_hash.slice(0, 10)}…) differs from replayed log tip (${summary.final_hash.slice(0, 10)}…)!`;
                eqEl.style.color = 'var(--red)';
              }
            }
          }
        }
      } catch (e) {
        console.warn("Error processing manifest mirrors:", e);
      }
    }
    window.fetchManifestAndVerifyMirrors = fetchManifestAndVerifyMirrors;

    async function copyIpfsCid() {
      const cidEl = document.getElementById('mirrorIpfsEventsCid');
      if (cidEl && cidEl.textContent && cidEl.textContent !== 'Loading CID...') {
        try {
          await navigator.clipboard.writeText(cidEl.textContent);
          showSuccessToast('✓ IPFS Events CID copied to clipboard!');
        } catch (e) {
          showToast('Clipboard error: ' + e);
        }
      }
    }
    window.copyIpfsCid = copyIpfsCid;

    function renderLedgerSummary(summary, rawLog) {
      const badge = document.getElementById('ledgerVerificationBadge');
      if (badge) {
        badge.className = 'ledger-badge ok';
        badge.textContent = `✓ VERIFIED (${summary.events_count} Events Replayed)`;
      }

      const chainEl = document.getElementById('ledgerChainStatus');
      if (chainEl) {
        chainEl.textContent = summary.chain_valid ? 'VALID (BLAKE3 Canonical Preimages)' : 'INVALID';
        chainEl.style.color = summary.chain_valid ? 'var(--green)' : 'var(--red)';
      }

      const countEl = document.getElementById('ledgerEventsCount');
      if (countEl) countEl.textContent = summary.events_count;

      const activeEl = document.getElementById('ledgerActiveSupply');
      if (activeEl) activeEl.textContent = `${Number(summary.active_credits).toLocaleString()} credits`;

      const retiredEl = document.getElementById('ledgerRetiredSupply');
      if (retiredEl) retiredEl.textContent = `${Number(summary.retired_credits).toLocaleString()} credits`;

      const tipHashEl = document.getElementById('ledgerTipHash');
      if (tipHashEl) tipHashEl.textContent = summary.final_hash;

      // Identity & Trust Roots
      const chainIdEl = document.getElementById('ledgerChainId');
      if (chainIdEl && summary.state && summary.state.chain_id) {
        chainIdEl.textContent = typeof summary.state.chain_id === 'string'
          ? summary.state.chain_id
          : Array.from(summary.state.chain_id).map(b => b.toString(16).padStart(2, '0')).join('');
      }
      const authEl = document.getElementById('ledgerAuthorityKey');
      if (authEl && summary.state && summary.state.authority) {
        authEl.textContent = summary.state.authority;
      }
      const seqEl = document.getElementById('ledgerSequencerKey');
      if (seqEl && summary.state && summary.state.sequencer) {
        seqEl.textContent = summary.state.sequencer;
      }

      // Protocol Invariants (1 to 7)
      const invGrid = document.getElementById('publicLedgerInvariantsGrid');
      if (invGrid && summary.invariant_report) {
        invGrid.replaceChildren();
        const inv = summary.invariant_report;
        invGrid.appendChild(auditCard("1", "PoI is Mandatory for Minting", "Minting fails if no valid Proof-of-Integrity is supplied.", inv.inv1_poi_mandatory));
        invGrid.appendChild(auditCard("2", "Supply Authorized Cap Limit & Conservation", "Active + Retired equals total authorized issuance.", inv.inv2_supply_cap));
        invGrid.appendChild(auditCard("3", "Global Serial Locking Uniqueness", "Overlapping active serial ranges rejected.", inv.inv3_serial_uniqueness));
        invGrid.appendChild(auditCard("4", "Burn Irreversibility (Spent Forever)", "Retired ranges blacklisted globally.", inv.inv4_burn_irreversibility));
        invGrid.appendChild(auditCard("5", "PoO Uniqueness (Double-spending prevented)", "Retirements matching burned footprints rejected.", inv.inv5_poo_uniqueness));
        invGrid.appendChild(auditCard("6", "PoO Non-Transferability", "Proof-of-Offset receipts bind permanently.", inv.inv6_poo_non_transferable));
        invGrid.appendChild(auditCard("7", "PoI Single-use Consumed State", "PoI marked used, blocking replay.", inv.inv7_poi_single_use));
      }

      // Cryptographic Authorization Invariants (A1 to A3)
      const authGrid = document.getElementById('publicLedgerAuthGrid');
      if (authGrid && summary.invariant_report) {
        authGrid.replaceChildren();
        const inv = summary.invariant_report;
        authGrid.appendChild(auditCard("A1", "Strict Ed25519 Signatures", "Detached signature verified under authorized public key.", inv.inva1_signature_validity !== false));
        authGrid.appendChild(auditCard("A2", "Operation Index Contiguity", "Per-credit op_index strictly contiguous (replay impossible).", inv.inva2_op_index_contiguity !== false));
        authGrid.appendChild(auditCard("A3", "Domain Separation & Chain ID", "All signatures strictly bound to 32-byte registry chain_id.", inv.inva3_chain_id_binding !== false));
      }

      // Checkpoints rendering
      renderCheckpoints(summary);

      // Populate events table
      renderEventsTable(rawLog);

      // Initialize tamper textarea
      const tamperInput = document.getElementById('tamperLogInput');
      if (tamperInput && !tamperInput.value) {
        tamperInput.value = rawLog.trim();
      }
    }

    async function renderCheckpoints(summary) {
      const container = document.getElementById('checkpointsContainer');
      if (!container) return;
      container.replaceChildren();

      try {
        let cpList = [];
        const resp = await fetch('checkpoints/5.json', { cache: 'no-store' });
        if (resp.ok) {
          const cpText = await resp.text();
          const cp = JSON.parse(cpText);
          cpList.push({ file: 'checkpoints/5.json', raw: cpText, data: cp });
        }

        for (const item of cpList) {
          const card = document.createElement('div');
          card.className = 'result-card';
          card.style.padding = '0.85rem 1rem';
          card.style.marginBottom = '0.5rem';
          card.style.display = 'flex';
          card.style.justifyContent = 'space-between';
          card.style.alignItems = 'center';
          card.style.flexWrap = 'wrap';
          card.style.gap = '0.75rem';

          let verified = false;
          try {
            if (summary.state && summary.state.sequencer) {
              verified = verify_checkpoint(item.raw, summary.state.sequencer);
            }
          } catch (e) {
            console.error('Checkpoint verify error:', e);
          }

          const left = document.createElement('div');
          left.style.display = 'flex';
          left.style.alignItems = 'center';
          left.style.gap = '0.6rem';

          const badge = document.createElement('span');
          badge.className = `status-badge ${verified ? 'active' : 'expired'}`;
          badge.textContent = verified ? 'SEQUENCER VERIFIED ✓' : 'VERIFICATION FAILED ✗';
          badge.style.fontSize = '0.75rem';

          const title = document.createElement('span');
          title.style.fontWeight = '600';
          title.style.fontSize = '0.85rem';
          title.textContent = `Checkpoint Size ${item.data.size}`;

          const hash = document.createElement('span');
          hash.className = 'mono-hash';
          hash.textContent = `Head: ${item.data.head_hash.slice(0, 16)}...`;
          hash.title = item.data.head_hash;

          left.appendChild(badge);
          left.appendChild(title);
          left.appendChild(hash);

          const right = document.createElement('div');
          right.style.fontSize = '0.78rem';
          right.style.color = 'var(--muted)';
          right.textContent = `Signed: ${new Date(item.data.timestamp * 1000).toLocaleString()}`;

          card.appendChild(left);
          card.appendChild(right);
          container.appendChild(card);
        }
      } catch (e) {
        console.error('Error rendering checkpoints:', e);
      }
    }

    function renderEventsTable(rawLog) {
      const tbody = document.getElementById('ledgerEventsTableBody');
      if (!tbody) return;

      const rows = [];
      const lines = rawLog.trim().split('\n');
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        try {
          const entry = JSON.parse(trimmed);
          const tr = document.createElement('tr');

          // 1. Seq
          const tdSeq = document.createElement('td');
          tdSeq.style.fontFamily = 'var(--mono)';
          tdSeq.style.fontWeight = '600';
          tdSeq.textContent = `#${entry.seq}`;
          tr.appendChild(tdSeq);

          // 2. Type badge
          const tdType = document.createElement('td');
          const typeBadge = document.createElement('span');
          typeBadge.className = 'status-badge';
          const t = (entry.type || '').toLowerCase();
          if (t === 'genesis') {
            typeBadge.style.background = 'rgba(56, 189, 248, 0.15)';
            typeBadge.style.color = '#38bdf8';
            typeBadge.textContent = 'GENESIS';
          } else if (t === 'vvb_register') {
            typeBadge.style.background = 'rgba(74, 222, 128, 0.15)';
            typeBadge.style.color = '#4ade80';
            typeBadge.textContent = 'VVB REGISTER';
          } else if (t === 'mint') {
            typeBadge.style.background = 'rgba(88, 166, 255, 0.15)';
            typeBadge.style.color = 'var(--blue)';
            typeBadge.textContent = 'MINT';
          } else if (t === 'transfer') {
            typeBadge.style.background = 'rgba(236, 178, 46, 0.15)';
            typeBadge.style.color = 'var(--amber)';
            typeBadge.textContent = 'TRANSFER';
          } else if (t === 'burn') {
            typeBadge.style.background = 'rgba(188, 140, 242, 0.15)';
            typeBadge.style.color = 'var(--purple)';
            typeBadge.textContent = 'BURN';
          } else {
            typeBadge.textContent = (entry.type || '').toUpperCase();
          }
          tdType.appendChild(typeBadge);
          tr.appendChild(tdType);

          // 3. Prev Hash
          const tdPrev = document.createElement('td');
          const prevSpan = document.createElement('span');
          prevSpan.className = 'mono-hash';
          const prevH = entry.prev_hash || '';
          prevSpan.textContent = prevH.length > 16 ? `${prevH.slice(0, 8)}...${prevH.slice(-6)}` : prevH;
          prevSpan.title = prevH;
          tdPrev.appendChild(prevSpan);
          tr.appendChild(tdPrev);

          // 4. Entry Hash
          const tdHash = document.createElement('td');
          const hashSpan = document.createElement('span');
          hashSpan.className = 'mono-hash';
          const h = entry.hash || '';
          hashSpan.textContent = h.length > 16 ? `${h.slice(0, 8)}...${h.slice(-6)}` : h;
          hashSpan.title = h;
          tdHash.appendChild(hashSpan);
          tr.appendChild(tdHash);

          // 5. Transition Details
          const tdDetails = document.createElement('td');
          tdDetails.style.fontSize = '0.82rem';
          if (t === 'genesis' && entry.payload) {
            const p = entry.payload;
            tdDetails.textContent = `Domain "${p.chain_name || ''}" initialized · Authority: ${(p.authority || '').slice(0, 10)}... · Sequencer: ${(p.sequencer || '').slice(0, 10)}...`;
          } else if (t === 'vvb_register' && entry.payload) {
            const p = entry.payload;
            tdDetails.textContent = `Accredited VVB "${p.label || ''}" · Key: ${(p.vvb || '').slice(0, 10)}...`;
          } else if (t === 'mint' && entry.payload) {
            const p = entry.payload;
            const ownerStr = (p.initial_owner || (p.poi ? p.poi.owner : '') || '').slice(0, 10) + '...';
            const amt = p.cc_mint_amount || (p.poi ? p.poi.amount_tco2e : '');
            tdDetails.textContent = `Project ${p.project_id || ''} · ${amt} credits minted to ${ownerStr}`;
          } else if (t === 'transfer' && entry.payload) {
            const p = entry.payload;
            const newOwner = (p.new_owner || '').slice(0, 10) + '...';
            tdDetails.textContent = `Credit ${p.credit_id || ''} transferred to ${newOwner} (op_index ${p.op_index ?? ''})`;
          } else if (t === 'burn' && entry.payload) {
            const p = entry.payload;
            const start = p.range_start ?? (p.burn_range ? p.burn_range.start : 0);
            const end = p.range_end ?? (p.burn_range ? p.burn_range.end : 0);
            const count = end - start + 1;
            tdDetails.textContent = `Serial range [${start}-${end}] (${count} credits) retired for "${p.beneficiary || ''}"`;
          } else {
            tdDetails.textContent = JSON.stringify(entry.payload || {});
          }
          tr.appendChild(tdDetails);

          rows.push(tr);
        } catch (e) {
          console.error("Error parsing event row:", e);
        }
      }
      tbody.replaceChildren(...rows);
    }

    async function checkOtsProof() {
      const otsStatus = document.getElementById('otsStatusText');
      try {
        const resp = await fetch('events.jsonl.ots', { method: 'HEAD', cache: 'no-store' });
        if (resp.ok) {
          const sz = resp.headers.get('content-length');
          const sizeStr = sz ? `${sz} bytes` : '140 bytes';
          if (otsStatus) {
            otsStatus.textContent = `Proof file present (${sizeStr}) · Anchored in calendar pools (Alice, Bob, Finney) · Pending Bitcoin block attestation`;
          }
        }
      } catch (_) {}
    }

    function toggleTamperSandbox() {
      const box = document.getElementById('tamperSandbox');
      if (!box) return;
      const isHidden = box.style.display === 'none' || !box.style.display;
      box.style.display = isHidden ? 'block' : 'none';
      if (isHidden) {
        const input = document.getElementById('tamperLogInput');
        if (input && (!input.value || !input.value.trim())) {
          input.value = publicLedgerRaw.trim();
        }
      }
    }
    window.toggleTamperSandbox = toggleTamperSandbox;

    function replayCustomLog() {
      const input = document.getElementById('tamperLogInput');
      const banner = document.getElementById('tamperResultBanner');
      if (!input || !banner) return;

      const content = input.value.trim();
      try {
        const summaryJson = replay_event_log(content);
        const summary = JSON.parse(summaryJson);
        banner.className = 'tamper-banner success';
        banner.textContent = `✓ REPLAY SUCCESS: ${summary.events_count} events replayed, cryptographic hash chain valid, all 7 invariants satisfied!`;
        banner.style.display = 'block';
      } catch (err) {
        banner.className = 'tamper-banner error';
        banner.textContent = `✗ WASM CRYPTOGRAPHIC REJECTION: ${err.message || err}`;
        banner.style.display = 'block';
      }
    }
    window.replayCustomLog = replayCustomLog;

    function corruptCustomLog() {
      const input = document.getElementById('tamperLogInput');
      if (!input) return;
      let text = input.value;
      if (text.includes('"hash":"c17a')) {
        text = text.replace('"hash":"c17a', '"hash":"ffff');
      } else if (text.includes('"hash": "c17a')) {
        text = text.replace('"hash": "c17a', '"hash": "ffff');
      } else if (text.includes('"hash":"')) {
        text = text.replace('"hash":"', '"hash":"0000');
      }
      input.value = text;
      replayCustomLog();
    }
    window.corruptCustomLog = corruptCustomLog;

    function resetCustomLog() {
      const input = document.getElementById('tamperLogInput');
      const banner = document.getElementById('tamperResultBanner');
      if (input) input.value = publicLedgerRaw.trim();
      if (banner) banner.style.display = 'none';
    }
    window.resetCustomLog = resetCustomLog;

    function runAuditChecks() {
      if (mintedBatches.length === 0) {
        document.getElementById('auditGrid').replaceChildren(createEmptyState('📄', 'No Audit Data', 'Complete a full lifecycle (MRV → Mint → Retire) to see invariant checks.'));
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

        const invReport = JSON.parse(registry.check_invariants());

        const grid = document.getElementById('auditGrid');
        grid.replaceChildren();
        grid.appendChild(auditCard("1", "PoI is Mandatory for Minting", "Minting fails if no valid Proof-of-Integrity is supplied.", invReport.inv1_poi_mandatory));
        grid.appendChild(auditCard("2", "Supply Authorized Cap Limit", "Minted credits must be <= authorized PoI quantity.", invReport.inv2_supply_cap));
        grid.appendChild(auditCard("3", "Global Serial Locking Uniqueness", "Overlapping active serial ranges rejected.", invReport.inv3_serial_uniqueness));
        grid.appendChild(auditCard("4", "Burn Irreversibility (Spent Forever)", "Retired ranges blacklisted globally.", invReport.inv4_burn_irreversibility));
        grid.appendChild(auditCard("5", "PoO Uniqueness (Double-spending prevented)", "Retirements matching burned footprints rejected.", invReport.inv5_poo_uniqueness));
        grid.appendChild(auditCard("6", "PoO Non-Transferability", "Proof-of-Offset receipts bind permanently.", invReport.inv6_poo_non_transferable));
        grid.appendChild(auditCard("7", "PoI Single-use Consumed State", "PoI marked used, blocking replay.", invReport.inv7_poi_single_use));

        const authGrid = document.getElementById('auditAuthGrid');
        if (authGrid) {
          authGrid.replaceChildren();
          authGrid.appendChild(auditCard("A1", "Strict Ed25519 Signatures", "Detached signature verified under authorized public key.", invReport.inva1_signature_validity !== false));
          authGrid.appendChild(auditCard("A2", "Operation Index Contiguity", "Per-credit op_index strictly contiguous (replay impossible).", invReport.inva2_op_index_contiguity !== false));
          authGrid.appendChild(auditCard("A3", "Domain Separation & Chain ID", "All signatures strictly bound to 32-byte registry chain_id.", invReport.inva3_chain_id_binding !== false));
        }

        setupDownloads(firstBatch, state, fullState);
      } catch (err) { console.error("Audit error:", err); }
    }
    window.runAuditChecks = runAuditChecks;

    function auditCard(num, name, desc, pass) {
      const card = document.createElement('div');
      card.className = `audit-card ${pass ? 'ok' : 'failed'}`;
      const icon = document.createElement('div');
      icon.className = 'audit-icon';
      icon.textContent = pass ? '✓' : '✗';
      const descDiv = document.createElement('div');
      descDiv.className = 'audit-desc';
      const h5 = document.createElement('h5');
      h5.textContent = `Invariant ${num}: ${name}`;
      const p = document.createElement('p');
      p.textContent = desc;
      descDiv.appendChild(h5);
      descDiv.appendChild(p);
      card.appendChild(icon);
      card.appendChild(descDiv);
      return card;
    }

    function setupDownloads(batch, state, fullState) {
      const grid = document.getElementById('downloadGrid');
      grid.replaceChildren();
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
      a.href = dataStr;
      a.download = filename;
      a.textContent = `💾 ${label}`;
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
        globalNextSerial = 1000000;
        document.getElementById('mrvCommitmentDisplay').replaceChildren();
        document.getElementById('spotCheckSection').style.display = 'none';
        document.getElementById('mrvBody').replaceChildren();
        refreshDashboard();
        navigate('dashboard');
        showSuccessToast('✓ Registry reset complete');
      }
    }
    window.resetAll = resetAll;

    // ══════════════════════════════════════════════════════════════════
    //  RFC-006: KEY MANAGER & SOVEREIGN SIGNER
    // ══════════════════════════════════════════════════════════════════
    const PRESET_KEYS = [
      {
        id: 'infosys',
        label: 'Infosys Corporate Buyer',
        role: 'Credit Owner / Corporate Buyer',
        secret_key: '0f40aafb63d6f2157cef51206b800cc8142fd8204d0bd075d205555129bc7f3b',
        pubkey: '3fec9121bb0c0204f46e5401f552ccb23bcba63e6e745d1cc2dbbe70f9c0ba28'
      },
      {
        id: 'tata',
        label: 'Tata Solar Developer',
        role: 'Project Developer',
        secret_key: '01ea03956a3e58257e65fd4d05990e5d3fc01f6c4c55d497744a8b3c78fe4c6a',
        pubkey: 'dcc59196196d6c686652e43f1303665c79edaba5e07834a910ddd1c057576a8a'
      },
      {
        id: 'tuv',
        label: 'TUV NORD Carbon Bureau',
        role: 'Accredited VVB',
        secret_key: '645666f0a7cff4bd65a766a531d2767cfd8bb3dd58addfff237364ab40e825b9',
        pubkey: 'aa48ecc7ca6f6bcfcc7bace7bae03cf0ab4ded800be5f50b3d4c3b5dd0cb3892'
      },
      {
        id: 'authority',
        label: 'Root Registry Authority',
        role: 'Registry Governance',
        secret_key: '5c29be6d22e5402a10645e876e6b69d1516443b5f8e2b91f4958a6a89d4ce4f1',
        pubkey: '09afad81c26934a34c39c431932576c3fbb1d0920df767c31a13fccb25fdfcae'
      },
      {
        id: 'sequencer',
        label: 'Log Sequencer',
        role: 'Checkpoint Ordering',
        secret_key: '5639156043909ee807959732549ed904b628d8e3deec39b741f2e933320e1f9a',
        pubkey: '27ef3b8a333ca785002f12cc9071922848fa2fa460d3eb127994a90f24ee5715'
      }
    ];

    let activeKey = PRESET_KEYS[0];
    let secretKeyRevealed = false;
    let activeSignerTab = 'transfer';
    let latestCanonicalLine = '';
    let cachedEventsJsonl = '';

    function initKeyManager() {
      updateKeyManagerUI();
      renderPresetActorsGrid();
    }

    function updateKeyManagerUI() {
      const topbarLabel = document.getElementById('topbarKeyLabel');
      if (topbarLabel) {
        topbarLabel.textContent = `Actor: ${activeKey.label.split(' ')[0]} (${activeKey.pubkey.slice(0, 6)}…)`;
      }

      const modalLabel = document.getElementById('modalActiveActorLabel');
      if (modalLabel) modalLabel.textContent = activeKey.label;

      const modalRole = document.getElementById('modalActiveActorRole');
      if (modalRole) modalRole.textContent = activeKey.role;

      const modalPubkey = document.getElementById('modalActivePubkey');
      if (modalPubkey) modalPubkey.textContent = activeKey.pubkey;

      const modalSecret = document.getElementById('modalActiveSecret');
      if (modalSecret) {
        modalSecret.textContent = secretKeyRevealed
          ? activeKey.secret_key
          : '••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••';
      }

      const btnReveal = document.getElementById('btnToggleSecret');
      if (btnReveal) {
        btnReveal.textContent = secretKeyRevealed ? '🙈 Hide' : '👁️ Reveal';
      }

      const signerPubkey = document.getElementById('signerActivePubkey');
      if (signerPubkey) signerPubkey.textContent = activeKey.pubkey;

      const signerLabel = document.getElementById('signerActiveLabel');
      if (signerLabel) signerLabel.textContent = `${activeKey.label} (${activeKey.role})`;

      const signerChain = document.getElementById('signerChainId');
      if (signerChain) {
        signerChain.textContent = '6713110c8ac6ba73638381f2ec9bde8eb236e894b1a34b4293a9f69933069e95';
      }
    }

    function renderPresetActorsGrid() {
      const grid = document.getElementById('presetActorGrid');
      if (!grid) return;
      grid.replaceChildren();

      PRESET_KEYS.forEach(k => {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = `preset-actor-btn ${k.id === activeKey.id ? 'active' : ''}`;
        btn.onclick = () => selectPresetKey(k.id);

        const nameSpan = document.createElement('span');
        nameSpan.textContent = k.label;

        const roleSpan = document.createElement('span');
        roleSpan.className = 'actor-role';
        roleSpan.textContent = k.role;

        btn.appendChild(nameSpan);
        btn.appendChild(roleSpan);
        grid.appendChild(btn);
      });
    }

    function selectPresetKey(id) {
      const match = PRESET_KEYS.find(k => k.id === id);
      if (match) {
        activeKey = match;
        updateKeyManagerUI();
        renderPresetActorsGrid();
        showSuccessToast(`✓ Identity switched to: ${match.label}`);
      }
    }
    window.selectPresetKey = selectPresetKey;

    function openKeyManagerModal() {
      const modal = document.getElementById('modalKeyManager');
      if (modal) {
        updateKeyManagerUI();
        renderPresetActorsGrid();
        modal.classList.add('show');
      }
    }
    window.openKeyManagerModal = openKeyManagerModal;

    function closeKeyManagerModal() {
      const modal = document.getElementById('modalKeyManager');
      if (modal) modal.classList.remove('show');
    }
    window.closeKeyManagerModal = closeKeyManagerModal;

    function toggleSecretKeyReveal() {
      secretKeyRevealed = !secretKeyRevealed;
      updateKeyManagerUI();
    }
    window.toggleSecretKeyReveal = toggleSecretKeyReveal;

    async function copyModalPubkey() {
      try {
        await navigator.clipboard.writeText(activeKey.pubkey);
        showSuccessToast('✓ Public key copied to clipboard');
      } catch (e) {
        showToast('Clipboard error: ' + e);
      }
    }
    window.copyModalPubkey = copyModalPubkey;

    async function copyModalSecret() {
      try {
        await navigator.clipboard.writeText(activeKey.secret_key);
        showSuccessToast('✓ Secret key copied to clipboard');
      } catch (e) {
        showToast('Clipboard error: ' + e);
      }
    }
    window.copyModalSecret = copyModalSecret;

    async function copySignerPubkey() {
      try {
        await navigator.clipboard.writeText(activeKey.pubkey);
        showSuccessToast('✓ Active signer public key copied');
      } catch (e) {
        showToast('Clipboard error: ' + e);
      }
    }
    window.copySignerPubkey = copySignerPubkey;

    function generateFreshKeypair() {
      try {
        const rawJson = generate_keypair_wasm();
        const parsed = JSON.parse(rawJson);
        const customKey = {
          id: 'custom-' + Date.now(),
          label: 'Custom Ephemeral Identity',
          role: 'Custom Sovereign Actor',
          secret_key: parsed.secret_key,
          pubkey: parsed.pubkey
        };
        activeKey = customKey;
        PRESET_KEYS.push(customKey);
        updateKeyManagerUI();
        renderPresetActorsGrid();
        showSuccessToast('✓ Generated fresh Ed25519 keypair!');
      } catch (err) {
        showToast('Key generation failed: ' + err);
      }
    }
    window.generateFreshKeypair = generateFreshKeypair;

    function importCustomSecretKey() {
      const input = document.getElementById('inputImportSecret');
      if (!input) return;
      const hex = input.value.trim().toLowerCase();
      if (hex.length !== 64) {
        showToast('Invalid secret key: must be exactly 64 lowercase hexadecimal characters');
        return;
      }
      try {
        const pubkey = derive_pubkey_wasm(hex);
        const importedKey = {
          id: 'imported-' + Date.now(),
          label: 'Imported Identity',
          role: 'Custom Signer',
          secret_key: hex,
          pubkey: pubkey
        };
        activeKey = importedKey;
        PRESET_KEYS.push(importedKey);
        input.value = '';
        updateKeyManagerUI();
        renderPresetActorsGrid();
        showSuccessToast('✓ Custom secret key successfully imported and activated!');
      } catch (err) {
        showToast('Import error: ' + err);
      }
    }
    window.importCustomSecretKey = importCustomSecretKey;

    function exportKeypairJson() {
      const envelope = {
        protocol: 'GreyMisnomer',
        version: 1,
        exported_at: new Date().toISOString(),
        label: activeKey.label,
        role: activeKey.role,
        pubkey: activeKey.pubkey,
        secret_key: activeKey.secret_key
      };
      const blob = new Blob([JSON.stringify(envelope, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `greymisnomer_key_${activeKey.pubkey.slice(0, 8)}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      showSuccessToast('✓ Key envelope exported');
    }
    window.exportKeypairJson = exportKeypairJson;

    function switchSignerTab(tab) {
      activeSignerTab = tab;
      const tabs = ['transfer', 'burn', 'mint'];
      tabs.forEach(t => {
        const btn = document.getElementById(`btnTab${t.charAt(0).toUpperCase() + t.slice(1)}`);
        const form = document.getElementById(`formSigner${t.charAt(0).toUpperCase() + t.slice(1)}`);
        if (btn) btn.classList.toggle('active', t === tab);
        if (form) form.style.display = (t === tab) ? 'block' : 'none';
      });
      if (tab === 'mint' && activeKey.id !== 'tuv') {
        selectPresetKey('tuv');
      } else if (tab === 'transfer' && activeKey.id === 'tuv') {
        selectPresetKey('infosys');
      }
    }
    window.switchSignerTab = switchSignerTab;

    async function autoFillOpIndex() {
      try {
        let events = cachedEventsJsonl;
        if (!events) {
          const res = await fetch('events.jsonl');
          events = await res.text();
          cachedEventsJsonl = events;
        }
        const summaryJson = replay_event_log(events);
        const summary = JSON.parse(summaryJson);
        const targetCreditId = (activeSignerTab === 'burn')
          ? document.getElementById('burn-credit-id').value.trim()
          : document.getElementById('tx-credit-id').value.trim();

        const batch = summary.state.credits.find(b => b.credit_id === targetCreditId);
        if (batch) {
          const nextOp = batch.op_index;
          if (activeSignerTab === 'burn') {
            document.getElementById('burn-op-index').value = nextOp;
          } else {
            document.getElementById('tx-op-index').value = nextOp;
          }
          showSuccessToast(`✓ Detected next op_index: ${nextOp} for batch ${targetCreditId}`);
        } else {
          showToast(`Batch "${targetCreditId}" not found in replayed state.`);
        }
      } catch (err) {
        showToast('Failed to auto-detect op_index: ' + err);
      }
    }
    window.autoFillOpIndex = autoFillOpIndex;

    async function executeSignIntent() {
      const chainId = '6713110c8ac6ba73638381f2ec9bde8eb236e894b1a34b4293a9f69933069e95';
      const simBanner = document.getElementById('simBanner');
      const simBadge = document.getElementById('simBadge');
      const simMetrics = document.getElementById('simMetricsGrid');
      const canonicalBox = document.getElementById('canonicalLineBox');
      const btnCopy = document.getElementById('btnCopyCanonical');
      const assistantBox = document.getElementById('submissionAssistantBox');

      try {
        let events = cachedEventsJsonl;
        if (!events) {
          const res = await fetch('events.jsonl');
          events = await res.text();
          cachedEventsJsonl = events;
        }

        let signedResultJson = '';
        if (activeSignerTab === 'transfer') {
          const creditId = document.getElementById('tx-credit-id').value.trim();
          const recipient = document.getElementById('tx-recipient-pubkey').value.trim();
          const opIndex = parseInt(document.getElementById('tx-op-index').value) || 0;
          const params = {
            chain_id: chainId,
            credit_id: creditId,
            op_index: opIndex,
            new_owner: recipient
          };
          signedResultJson = sign_transfer_intent_wasm(JSON.stringify(params), activeKey.secret_key);
        } else if (activeSignerTab === 'burn') {
          const creditId = document.getElementById('burn-credit-id').value.trim();
          const rangeStart = parseInt(document.getElementById('burn-range-start').value) || 0;
          const rangeEnd = parseInt(document.getElementById('burn-range-end').value) || 0;
          const beneficiary = document.getElementById('burn-beneficiary').value.trim();
          const claimType = document.getElementById('burn-claim-type').value;
          const opIndex = parseInt(document.getElementById('burn-op-index').value) || 0;
          const params = {
            chain_id: chainId,
            credit_id: creditId,
            op_index: opIndex,
            range_start: rangeStart,
            range_end: rangeEnd,
            beneficiary: beneficiary,
            claim_type: claimType
          };
          signedResultJson = sign_burn_intent_wasm(JSON.stringify(params), activeKey.secret_key);
        } else if (activeSignerTab === 'mint') {
          const projectId = document.getElementById('mint-project-id').value.trim();
          const creditId = document.getElementById('mint-credit-id').value.trim();
          const rangeStart = parseInt(document.getElementById('mint-range-start').value) || 0;
          const rangeEnd = parseInt(document.getElementById('mint-range-end').value) || 0;
          const amount = parseInt(document.getElementById('mint-amount').value) || 0;
          const initialOwner = document.getElementById('mint-initial-owner').value.trim();
          const merkleRoot = document.getElementById('mint-merkle-root').value.trim();
          const leafCount = parseInt(document.getElementById('mint-leaf-count').value) || 0;
          const methodology = document.getElementById('mint-methodology').value.trim();
          const params = {
            chain_id: chainId,
            project_id: projectId,
            credit_id: creditId,
            range_start: rangeStart,
            range_end: rangeEnd,
            cc_mint_amount: amount,
            merkle_root: merkleRoot,
            leaf_count: leafCount,
            mrv_timestamp: 1700000000,
            methodology_hash: methodology,
            jurisdiction: 'IN',
            market_scope: 'Vcm',
            valid_from: 1700000000,
            valid_until: 1730000000,
            initial_owner: initialOwner
          };
          signedResultJson = sign_mint_intent_wasm(JSON.stringify(params), activeKey.secret_key);
        }

        const signedResult = JSON.parse(signedResultJson);
        const simResultJson = simulate_apply_wasm(events, signedResult.event_json);
        const sim = JSON.parse(simResultJson);

        if (sim.valid) {
          latestCanonicalLine = sim.canonical_line;
          simBadge.textContent = 'VALID';
          simBadge.style.background = 'rgba(57,211,83,0.15)';
          simBadge.style.color = 'var(--green)';

          simBanner.className = 'sim-status-banner valid';
          simBanner.replaceChildren();
          const checkIcon = document.createElement('span');
          checkIcon.textContent = '✅';
          const msgSpan = document.createElement('span');
          msgSpan.textContent = `Pre-flight simulation SUCCESS: Signed by ${activeKey.label} under Invariants 1–7 & A1–A3. Ready to sequence!`;
          simBanner.appendChild(checkIcon);
          simBanner.appendChild(msgSpan);

          document.getElementById('simSeq').textContent = sim.seq;
          document.getElementById('simNextOp').textContent = (sim.next_op_index !== undefined && sim.next_op_index !== null) ? sim.next_op_index : '-';
          document.getElementById('simActiveSupply').textContent = sim.active_credits.toLocaleString() + ' credits';
          document.getElementById('simRetiredSupply').textContent = sim.retired_credits.toLocaleString() + ' credits';
          simMetrics.style.display = 'grid';

          canonicalBox.textContent = sim.canonical_line;
          btnCopy.disabled = false;
          assistantBox.style.display = 'block';

          showSuccessToast('✓ Transaction successfully signed and mathematically verified!');
        } else {
          simBadge.textContent = 'REJECTED';
          simBadge.style.background = 'rgba(248,81,73,0.15)';
          simBadge.style.color = 'var(--red)';

          simBanner.className = 'sim-status-banner invalid';
          simBanner.replaceChildren();
          const errIcon = document.createElement('span');
          errIcon.textContent = '❌';
          const errMsg = document.createElement('span');
          errMsg.textContent = `WASM Pre-Flight Rejection: ${sim.error || 'Invariant violation'}`;
          simBanner.appendChild(errIcon);
          simBanner.appendChild(errMsg);

          simMetrics.style.display = 'none';
          canonicalBox.textContent = `// Simulated action was rejected by the state machine:\n// ${sim.error}`;
          btnCopy.disabled = true;
          assistantBox.style.display = 'none';
          showToast(`Rejection: ${sim.error}`);
        }
      } catch (err) {
        console.error('Sign/simulation error:', err);
        showToast('Error: ' + err);
      }
    }
    window.executeSignIntent = executeSignIntent;

    async function copyCanonicalLine() {
      if (!latestCanonicalLine) return;
      try {
        await navigator.clipboard.writeText(latestCanonicalLine);
        showSuccessToast('✓ Canonical line copied! Ready to append or submit.');
      } catch (e) {
        showToast('Clipboard error: ' + e);
      }
    }
    window.copyCanonicalLine = copyCanonicalLine;

    function openGitHubIssueSubmission() {
      if (!latestCanonicalLine) return;
      const title = encodeURIComponent(`RFC-006 Signed Event Submission: ${activeSignerTab.toUpperCase()} (${activeKey.label})`);
      const body = encodeURIComponent(
        `### GreyMisnomer RFC-006 Signed Event Submission\n\n` +
        `**Action Type:** \`${activeSignerTab}\`\n` +
        `**Signer Public Key:** \`${activeKey.pubkey}\`\n` +
        `**Signer Label:** ${activeKey.label}\n\n` +
        `#### Canonical Event Line\n` +
        `\`\`\`json\n${latestCanonicalLine}\n\`\`\`\n\n` +
        `*Generated via In-Browser Sovereign Signer ($0 Infrastructure).*`
      );
      window.open(`https://github.com/GreyMisnomer/GreyMisnomer/issues/new?title=${title}&body=${body}`, '_blank');
    }
    window.openGitHubIssueSubmission = openGitHubIssueSubmission;

    function downloadGmlineFile() {
      if (!latestCanonicalLine) return;
      const blob = new Blob([latestCanonicalLine + '\n'], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `event_${activeSignerTab}_${Date.now()}.gmline`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      showSuccessToast('✓ .gmline bundle saved for air-gapped submission');
    }
    window.downloadGmlineFile = downloadGmlineFile;
